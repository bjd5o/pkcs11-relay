// relay-ffi's `CardChannel` over CoreNFC (ISO 7816, PIV AID A000000308 in Info.plist).
//
// Rust calls these methods from a background thread: `beginSession` opens the NFC sheet and
// waits for the tap, `transmit` moves one APDU, `endSession` closes the sheet. The card loses
// power when the session ends, which also clears its PIN state; over NFC the tap is the touch.
// Never called on the main thread (the waits would block the UI).

import Foundation

#if canImport(CoreNFC) && os(iOS)
import CoreNFC

final class NFCCard: NSObject, CardChannel, NFCTagReaderSessionDelegate, @unchecked Sendable {
    private let queue = DispatchQueue(label: "relay.nfc")
    private let message: String
    private var session: NFCTagReaderSession?
    private var tag: NFCISO7816Tag?
    private var connected = DispatchSemaphore(value: 0)
    private var failure: String?

    init(message: String) {
        self.message = message
    }

    static var isAvailable: Bool { NFCTagReaderSession.readingAvailable }

    func beginSession() throws {
        failure = nil
        tag = nil
        connected = DispatchSemaphore(value: 0)
        guard let s = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: queue) else {
            throw PlatformError.Failed(message: "NFC is not available")
        }
        s.alertMessage = message
        session = s
        s.begin()
        // The system sheet times out after about 60 s.
        if connected.wait(timeout: .now() + 65) == .timedOut {
            s.invalidate()
            throw PlatformError.Failed(message: "no YubiKey was tapped")
        }
        if let f = failure { throw PlatformError.Failed(message: f) }
    }

    func transmit(apdu: Data) throws -> Data {
        guard let tag, let cmd = NFCISO7816APDU(data: apdu) else {
            throw PlatformError.Failed(message: "no card session")
        }
        let done = DispatchSemaphore(value: 0)
        var out: Result<Data, Error> = .failure(PlatformError.Failed(message: "no answer"))
        tag.sendCommand(apdu: cmd) { data, sw1, sw2, error in
            if let error {
                out = .failure(error)
            } else {
                out = .success(data + Data([sw1, sw2]))
            }
            done.signal()
        }
        if done.wait(timeout: .now() + 30) == .timedOut {
            throw PlatformError.Failed(message: "the YubiKey stopped answering")
        }
        switch out {
        case .success(let d): return d
        case .failure(let e): throw PlatformError.Failed(message: e.localizedDescription)
        }
    }

    func endSession() {
        session?.alertMessage = "Done"
        session?.invalidate()
        session = nil
        tag = nil
    }

    // MARK: NFCTagReaderSessionDelegate

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        if tag == nil {
            failure = error.localizedDescription
            connected.signal()
        }
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let first = tags.first, case .iso7816(let iso) = first else {
            session.invalidate(errorMessage: "Not a YubiKey")
            return
        }
        session.connect(to: first) { [weak self] error in
            guard let self else { return }
            if let error {
                self.failure = error.localizedDescription
            } else {
                self.tag = iso
            }
            self.connected.signal()
        }
    }
}
#endif

/// Which card channel to use for one operation.
enum CardSource {
    static func make(message: String) throws -> CardChannel {
        #if RELAY_TEST_CARD
        // Simulator end-to-end test only: a software PIV card from relay-ffi's test-card build.
        if let json = ProcessInfo.processInfo.environment["RELAY_TEST_CARD"] {
            return try testCard(slotsJson: json)
        }
        #endif
        #if canImport(CoreNFC) && os(iOS)
        guard NFCCard.isAvailable else {
            throw PlatformError.Failed(message: "This device cannot read NFC")
        }
        return NFCCard(message: message)
        #else
        // macOS and iPad over USB come in Part B (relay-pcsc / TKSmartCard).
        throw PlatformError.Failed(message: "No YubiKey reader on this platform yet")
        #endif
    }
}
