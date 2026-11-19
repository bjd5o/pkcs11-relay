// App state and every call into relay-ffi. All checks, signing and card logic are in Rust;
// this file only sequences the person's actions: biometric, PIN, tap.

import Foundation
import LocalAuthentication
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    @Published var setup: SetupFile?
    enum Tab: Hashable { case requests, clients, status }
    @Published var tab: Tab = .requests
    /// The APNs device token, kept until the approver exists to send it.
    private var pushToken: String?

    /// A scanned setup link, checked and waiting for the person to confirm it.
    @Published private(set) var preview: SetupPreview?
    @Published private(set) var approver: Approver?
    @Published private(set) var status: Status?
    @Published private(set) var inbox = Inbox(requests: [], pairings: [], rejected: 0, rejections: [])
    /// The Clients and Approvers screens: verified here, refreshed by `syncClients`.
    @Published private(set) var clients: [ClientInfo] = []
    @Published private(set) var approvers: [ApproverInfo] = []
    @Published var error: String?
    @Published private(set) var busy: String?
    /// Keys the first enrollment tap found, and what it read slot by slot.
    @Published private(set) var discovered: [KeyInfo]?
    @Published private(set) var discoveryReport = ""

    private var deviceKey: EnclaveKey?
    private var authKey: EnclaveKey?
    private var adminKey: EnclaveKey?
    /// When the admin key's biometric context was evaluated: it lasts an hour at most, and
    /// ends when the app goes to the background (wire-format §8.5).
    private var adminUnlockedAt: Date?
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
        busy = "Checking the setup link"
        defer { busy = nil; linkRetryNow = false }
        // A relay on the local network is unreachable until the person allows Local Network
        // access, and iOS/macOS ask only on the first attempt, while that attempt fails. So a
        // relay error is retried for about a minute, and at once when the app becomes active
        // again (the permission prompt closing). Retrying only repeats the fetches; every check
        // still runs on the attempt that succeeds. Other errors (bad signature, expired link)
        // are shown straight away.
        var last: Error?
        for delay in [0, 2, 3, 5, 5, 10, 10, 15, 15] {
            if delay > 0 {
                busy = "Can't reach the relay yet. If asked, allow Local Network access."
                for _ in 0..<(delay * 4) where !linkRetryNow {
                    try? await Task.sleep(for: .milliseconds(250))
                }
                linkRetryNow = false
            }
            do {
                preview = try await Self.background { try setupFromLink(link: link, overrides: overrides) }
                return
            } catch let e as RelayError {
                guard case .Relay = e else { show(e); return }
                last = e
            } catch {
                show(error)
                return
            }
        }
        if let last { show(last) }
    }

    /// Set when the app becomes active, so a waiting setup-link check retries now.
    private var linkRetryNow = false

    func becameActive() {
        if preview == nil, setup == nil, busy != nil { linkRetryNow = true }
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
            let admin = try EnclaveKey(.admin)
            self.deviceKey = device
            self.authKey = auth
            self.adminKey = admin
            let saved = Storage.loadState()
            let config = setup.config
            let a = try await Self.background {
                try Approver(config: config, deviceKey: device, authKey: auth, adminKey: admin, saved: saved)
            }
            self.approver = a
            self.refresh()
            self.startPolling()
            if let t = self.pushToken { self.setPushToken(t) }
        }
    }

    // MARK: push

    /// The system's APNs token: registered with the relay so it can ring this device.
    func setPushToken(_ hex: String) {
        pushToken = hex
        guard let a = approver else { return }
        Task {
            do {
                try await Self.background { try a.setPushToken(token: hex) }
            } catch {
                NSLog("relay-push: could not register the token: %@", error.localizedDescription)
            }
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
    /// The card for one operation: a plugged-in USB key, or NFC with `nfc` on the tap sheet.
    /// With USB the person may need to touch the key, so the status line says so.
    private func card(nfc: String) async throws -> CardChannel {
        let card = try await Self.background { try CardSource.make(message: nfc) }
        if card is USBCard {
            busy = "Touch your YubiKey if it blinks"
        }
        return card
    }

    func readYubiKey() async {
        guard let a = approver else { return }
        await run("Reading the YubiKey") {
            let card = try await self.card(nfc: "Hold your YubiKey to the iPhone to read its keys")
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
            let card = try await self.card(nfc: "Hold your YubiKey to the iPhone to enroll")
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
            let card = try await self.card(nfc: "Hold your YubiKey to the iPhone to \(r.operation)")
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

    /// Approve a pairing: Face ID, the PIN, then the card's attest key signs the client's grant.
    func approvePairing(_ p: PairingInfo, keys: [String], windowSecs: UInt64, pin: String) async -> Bool {
        guard let a = approver else { return false }
        var done = false
        await run("Approving the client") {
            // A local confirmation: approving a client is a security decision.
            _ = try await evaluateBiometrics(reason: "Approve client \(p.clientId)")
            let card = try await self.card(nfc: "Hold your YubiKey to sign client \(p.clientId)'s grant")
            let pin = Data(pin.utf8)
            try await Self.background {
                try a.approvePairing(clientId: p.clientId, keys: keys, windowSecs: windowSecs, card: card, pin: pin)
            }
            self.refresh()
            done = true
        }
        return done
    }

    // MARK: Clients and Approvers (admin key)

    /// The admin key's biometric context: evaluated when the screen needs it, reused for an
    /// hour, dropped when the app goes to the background.
    private func unlockAdmin() async throws {
        guard let a = approver, let admin = adminKey, let device = deviceKey else { return }
        if let at = adminUnlockedAt, Date().timeIntervalSince(at) < 3_600 { return }
        let ctx = try await evaluateBiometrics(reason: "Show and change your clients and approvers")
        admin.use(ctx)
        adminUnlockedAt = Date()
        // A device enrolled before admin keys binds it once, with the device key.
        if !a.adminEnabled() {
            device.use(ctx)
            defer { device.use(nil) }
            try await Self.background { try a.enableAdmin() }
        }
    }

    /// The app went to the background: the admin session ends.
    func lockAdmin() {
        adminKey?.use(nil)
        adminUnlockedAt = nil
    }

    /// Fetch every client's grant and every approver from the relay; both are verified here.
    func syncClients() async {
        guard let a = approver else { return }
        await run("Loading clients and approvers") {
            try await self.unlockAdmin()
            _ = try await Self.background { try a.syncClients() }
            self.approvers = try await Self.background { try a.approvers() }
            self.clients = a.clients()
            self.refresh()
        }
    }

    /// What this device knows without the relay (no biometric needed).
    func loadLocalClients() {
        clients = approver?.clients() ?? []
    }

    func changeClient(_ c: ClientInfo, keys: [String], windowSecs: UInt64, pin: String) async -> Bool {
        await clientAction("Changing \(c.clientId)", nfc: "Hold your YubiKey to sign the new grant", pin: pin) { a, card, pin in
            try a.changeClient(clientId: c.clientId, keys: keys, windowSecs: windowSecs, card: card, pin: pin)
        }
    }

    func renewClient(_ c: ClientInfo, pin: String) async -> Bool {
        await clientAction("Renewing \(c.clientId)", nfc: "Hold your YubiKey to renew the grant", pin: pin) { a, card, pin in
            try a.renewClient(clientId: c.clientId, card: card, pin: pin)
        }
    }

    func revokeClient(_ c: ClientInfo, pin: String) async -> Bool {
        await clientAction("Revoking \(c.clientId)", nfc: "Hold your YubiKey to sign the revocation", pin: pin) { a, card, pin in
            try a.revokeClient(clientId: c.clientId, card: card, pin: pin)
        }
    }

    private func clientAction(
        _ what: String, nfc: String, pin: String,
        _ f: @escaping @Sendable (Approver, CardChannel, Data) throws -> Void
    ) async -> Bool {
        guard let a = approver else { return false }
        var done = false
        await run(what) {
            try await self.unlockAdmin()
            let card = try await self.card(nfc: nfc)
            let pin = Data(pin.utf8)
            try await Self.background { try f(a, card, pin) }
            self.clients = a.clients()
            self.refresh()
            done = true
        }
        return done
    }

    func retryPin() {
        approver?.clearPinFailure()
        refresh()
    }

    // MARK: helpers

    private func dropRequest(_ id: String) {
        inbox = Inbox(
            requests: inbox.requests.filter { $0.requestId != id },
            pairings: inbox.pairings, rejected: inbox.rejected, rejections: inbox.rejections)
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
