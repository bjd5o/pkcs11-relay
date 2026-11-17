// App state and every call into relay-ffi. All checks, signing and card logic are in Rust;
// this file only sequences the person's actions: biometric, PIN, tap.

import Foundation
import LocalAuthentication
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    @Published var setup: SetupFile?
    @Published private(set) var approver: Approver?
    @Published private(set) var status: Status?
    @Published private(set) var inbox = Inbox(requests: [], pairings: [], rejected: 0)
    @Published var error: String?
    @Published private(set) var busy: String?

    private var deviceKey: EnclaveKey?
    private var authKey: EnclaveKey?
    private var pollTask: Task<Void, Never>?

    init() {
        setup = Storage.loadSetup()
        #if RELAY_TEST_CARD
        // Simulator end-to-end test only (tests/sim-e2e.sh): the setup arrives in the
        // environment instead of through the file picker.
        // Each test run starts from scratch: no stored state or keys from an earlier run.
        if let json = ProcessInfo.processInfo.environment["RELAY_TEST_SETUP"],
           let s = try? JSONDecoder().decode(SetupFile.self, from: Data(json.utf8)) {
            Storage.reset()
            EnclaveKey.reset()
            try? Storage.saveSetup(s)
            setup = s
        }
        #endif
        if setup != nil { Task { await connect() } }
    }

    // MARK: setup

    /// Read a setup file and return it with the signer fingerprint for the person to confirm.
    func readSetup(_ data: Data) throws -> (SetupFile, String) {
        let s = try JSONDecoder().decode(SetupFile.self, from: data)
        return (s, try manifestSignerFingerprint(armored: s.manifest_signer))
    }

    func confirmSetup(_ s: SetupFile) async {
        do {
            try Storage.saveSetup(s)
            setup = s
            await connect()
        } catch { show(error) }
    }

    func reset() {
        pollTask?.cancel()
        approver = nil
        status = nil
        setup = nil
        Storage.reset()
        EnclaveKey.reset()
    }

    /// Create the keys if needed, fetch and verify the manifest, restore the saved state.
    func connect() async {
        guard let setup else { return }
        await run("Connecting to the relay") {
            let device = try EnclaveKey(.device)
            let auth = try EnclaveKey(.auth)
            self.deviceKey = device
            self.authKey = auth
            let saved = Storage.loadState()
            let config = setup.config
            let a = try await Self.background {
                try Approver(config: config, deviceKey: device, authKey: auth, saved: saved)
            }
            self.approver = a
            self.refresh()
            self.startPolling()
        }
    }

    // MARK: polling

    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let a = await self?.approver else { return }
                do {
                    let inbox = try await Self.background { try a.poll(waitSecs: 25) }
                    await MainActor.run { self?.inbox = inbox }
                    // The relay answers at once while anything is pending: do not spin.
                    if !inbox.requests.isEmpty || !inbox.pairings.isEmpty {
                        try? await Task.sleep(for: .seconds(2))
                    }
                } catch {
                    NSLog("relay-approver: poll failed: %@", "\(error)")
                    try? await Task.sleep(for: .seconds(5))
                }
            }
        }
    }

    func refresh() {
        guard let a = approver else { return }
        status = a.status()
        try? Storage.saveState(a.savedState())
    }

    // MARK: actions (biometric, then PIN, then tap)

    func enroll(pin: String) async {
        guard let a = approver, let key = deviceKey else { return }
        await run("Enrolling") {
            key.use(try await evaluateBiometrics(reason: "Enroll this device as an approver"))
            defer { key.use(nil) }
            let card = try CardSource.make(message: "Hold your YubiKey to the iPhone to enroll")
            let pin = Data(pin.utf8)
            _ = try await Self.background { try a.enroll(card: card, pin: pin) }
            self.refresh()
        }
    }

    func approve(_ r: RequestView, pin: String) async -> ApprovalOutcome? {
        guard let a = approver, let key = deviceKey else { return nil }
        var outcome: ApprovalOutcome?
        await run("Approving") {
            key.use(try await evaluateBiometrics(reason: "Approve \(r.operation) with \(r.keyLabel)"))
            defer { key.use(nil) }
            let card = try CardSource.make(message: "Hold your YubiKey to the iPhone to \(r.operation)")
            let pin = Data(pin.utf8)
            outcome = try await Self.background {
                try a.approve(requestId: r.requestId, card: card, pin: pin)
            }
            self.dropRequest(r.requestId)
            self.refresh()
        }
        return outcome
    }

    func deny(_ r: RequestView) async {
        guard let a = approver, let key = deviceKey else { return }
        await run("Denying") {
            key.use(try await evaluateBiometrics(reason: "Deny this request"))
            defer { key.use(nil) }
            try await Self.background { try a.deny(requestId: r.requestId) }
            self.dropRequest(r.requestId)
        }
    }

    func answerRejections() async {
        guard let a = approver, let key = deviceKey else { return }
        await run("Answering rejected requests") {
            key.use(try await evaluateBiometrics(reason: "Deny requests that failed their checks"))
            defer { key.use(nil) }
            _ = try await Self.background { try a.answerRejections() }
        }
    }

    func approvePairing(_ p: PairingInfo, keys: [String]) async {
        guard let a = approver else { return }
        await run("Approving the client") {
            // A local confirmation: approving a client is a security decision.
            _ = try await evaluateBiometrics(reason: "Approve client \(p.clientId)")
            try await Self.background { try a.approvePairing(clientId: p.clientId, keys: keys) }
            self.refresh()
        }
    }

    func retryPin() {
        approver?.clearPinFailure()
        refresh()
    }

    // MARK: helpers

    private func dropRequest(_ id: String) {
        inbox = Inbox(
            requests: inbox.requests.filter { $0.requestId != id },
            pairings: inbox.pairings, rejected: inbox.rejected)
    }

    private func run(_ what: String, _ body: () async throws -> Void) async {
        busy = what
        defer { busy = nil }
        do { try await body() } catch { show(error) }
    }

    private func show(_ e: Error) {
        if let e = e as? RelayError { error = "\(e)" } else { error = e.localizedDescription }
    }

    /// relay-ffi calls block on the network or the card: never on the main thread.
    nonisolated static func background<T: Sendable>(_ f: @escaping @Sendable () throws -> T) async throws -> T {
        try await Task.detached(priority: .userInitiated) { try f() }.value
    }
}
