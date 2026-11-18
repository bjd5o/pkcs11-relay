// relay-ffi's `CardChannel` over a USB YubiKey, through CryptoTokenKit (`TKSmartCard`): Macs,
// USB-C iPads and USB-C iPhones (iOS/iPadOS 16+, the `com.apple.security.smartcard`
// entitlement).
//
// Rust calls these methods from a background thread. `beginSession` takes exclusive access to
// the card, `transmit` moves one APDU, `endSession` releases it. The card keeps power when the
// session ends, so `resetsOnEnd` is false and Rust ends every session with `VERIFY` P1=`FF`,
// which clears the PIN. Touch-policy keys blink and wait for a touch during the operation.

import CryptoTokenKit
import Foundation

final class USBCard: CardChannel, @unchecked Sendable {
    private let card: TKSmartCard

    private init(card: TKSmartCard) {
        self.card = card
    }

    /// The first USB smart card present, if any. Never on the main thread.
    static func connected() -> USBCard? {
        guard let manager = TKSmartCardSlotManager.default else { return nil }
        for name in manager.slotNames {
            let done = DispatchSemaphore(value: 0)
            var found: TKSmartCardSlot?
            manager.getSlot(withName: name) { slot in
                found = slot
                done.signal()
            }
            guard done.wait(timeout: .now() + 5) == .success, let slot = found,
                  slot.state == .validCard, let c = slot.makeSmartCard()
            else { continue }
            return USBCard(card: c)
        }
        return nil
    }

    /// Whether this device can reach USB smart cards at all.
    static var isAvailable: Bool { TKSmartCardSlotManager.default != nil }

    func beginSession() throws {
        let done = DispatchSemaphore(value: 0)
        var ok = false
        var failure: Error?
        card.beginSession { success, error in
            ok = success
            failure = error
            done.signal()
        }
        guard done.wait(timeout: .now() + 15) == .success else {
            throw PlatformError.Failed(message: "the YubiKey did not respond; another app may be using it")
        }
        guard ok else {
            throw PlatformError.Failed(
                message: failure?.localizedDescription ?? "the YubiKey is in use by another app")
        }
    }

    func transmit(apdu: Data) throws -> Data {
        let done = DispatchSemaphore(value: 0)
        var out: Result<Data, Error> = .failure(PlatformError.Failed(message: "no answer"))
        card.transmit(apdu) { data, error in
            if let error {
                out = .failure(error)
            } else if let data {
                out = .success(data)
            }
            done.signal()
        }
        // A touch-policy key waits up to 15 s for the touch; leave room for it.
        if done.wait(timeout: .now() + 30) == .timedOut {
            throw PlatformError.Failed(message: "the YubiKey stopped answering (no touch?)")
        }
        // Diagnostics for the Xcode console: the 4-byte header and the status word only, never
        // the data (a VERIFY carries the PIN; responses can carry results).
        let header = apdu.prefix(4).map { String(format: "%02X", $0) }.joined()
        switch out {
        case .success(let d):
            let sw = d.suffix(2).map { String(format: "%02X", $0) }.joined()
            NSLog("relay-usb: %@ -> %@ (%d bytes)", header, sw, max(d.count - 2, 0))
            return d
        case .failure(let e):
            NSLog("relay-usb: %@ -> error %@", header, e.localizedDescription)
            throw PlatformError.Failed(message: e.localizedDescription)
        }
    }

    func endSession() {
        card.endSession()
    }

    func resetsOnEnd() -> Bool {
        false
    }
}
