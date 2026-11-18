// App state and every call into relay-ffi. All checks, signing and card logic are in Rust;
// this file only sequences the person's actions: biometric, PIN, tap.

import Foundation
import LocalAuthentication
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    @Published var setup: SetupFile?
    /// A scanned setup link, checked and waiting for the person to confirm it.
    @Published private(set) var preview: SetupPreview?
    @Published private(set) var approver: Approver?
    @Published private(set) var status: Status?
    @Published private(set) var inbox = Inbox(requests: [], pairings: [], rejected: 0)
    @Published var error: String?
    @Published private(set) var busy: String?
    /// Keys the first enrollment tap found, and what it read slot by slot.
    @Published private(set) var discovered: [KeyInfo]?
    @Published private(set) var discoveryReport = ""

    private var deviceKey: EnclaveKey?
    private var authKey: EnclaveKey?
    private var pollTask: Task<Void, Never>?

    init() {
        setup = Storage.loadSetup()
        #if RELAY_TEST_CARD
        // Simulator end-to-end test only (tests/sim-e2e.sh): each run starts from scratch, and
        // the setup link arrives in the environment as if scanned.
        if let link = ProcessInfo.processInfo.environment["RELAY_TEST_LINK"] {
            Storage.reset()
            EnclaveKey.reset()
            setup = nil
            Task { await self.open(link: link) }
        }
        #endif
        if setup != nil { Task { await connect() } }
    }

    // MARK: setup

    /// Testing overrides from the simulator test's environment; none in a release build.
    private var setupOverrides: SetupOverrides {
        #if RELAY_TEST_CARD
        let env = ProcessInfo.processInfo.environment
        return SetupOverrides(
            keyserverUrl: env["RELAY_TEST_KEYSERVER"], attestationRootsPem: env["RELAY_TEST_ROOTS"])
        #else
        return SetupOverrides(keyserverUrl: nil, attestationRootsPem: nil)
        #endif
    }

    /// A `poh://setup?…` link was scanned or pasted: check it and everything it points at.
    func open(link: String) async {
        guard setup == nil else {
            error = "This app is already set up. Use Start over on the Status tab to set it up again."
            return
        }
        let overrides = setupOverrides
        await run("Checking the setup link") {
            let p = try await Self.background { try setupFromLink(link: link, overrides: overrides) }
            self.preview = p
        }
    }

    func cancelSetup() {
        preview = nil
    }

    /// The person compared the fingerprint and chose a window: save and connect.
    func confirmSetup(windowSecs: UInt64) async {
        guard let p = preview else { return }
        do {
            let s = SetupFile(preview: p, windowSecs: windowSecs, rootsPem: setupOverrides.attestationRootsPem)
            try Storage.saveSetup(s)
            preview = nil
            setup = s
            await connect()
        } catch { show(error) }
    }

    func reset() {
        pollTask?.cancel()
        approver = nil
        status = nil
        setup = nil
        preview = nil
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

    /// Enrollment, first tap (no PIN): read which manifest keys the YubiKey holds.
    func readYubiKey() async {
        guard let a = approver else { return }
        await run("Reading the YubiKey") {
            let card = try CardSource.make(message: "Hold your YubiKey to the iPhone to read its keys")
            let keys = try await Self.background { try a.discover(card: card) }
            self.discovered = keys
            self.discoveryReport = a.lastDiscovery()
        }
    }

    /// Whether the first tap found the manifest's attest key.
    var attestKeyFound: Bool { discovered?.contains { $0.role == "attest" } ?? false }

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
