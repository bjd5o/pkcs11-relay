// The prototype's host app: sets up the software keys and the token, answers handed-off requests
// (standing in for the approval screen and the YubiKey), shows the call log, and has the optional
// iOS 26 NFC smart-card check.

import CryptoKit
import CryptoTokenKit
import Security
import SwiftUI
import UserNotifications
#if os(macOS)
import AppKit
#endif

@main
struct CTKProtoApp: App {
    @StateObject private var model = Model()
    var body: some Scene {
        WindowGroup { ContentView().environmentObject(model) }
    }
}

enum ItemSet: String, CaseIterable, Identifiable {
    case certificate, bare, both
    var id: String { rawValue }
}

@MainActor
final class Model: NSObject, ObservableObject, UNUserNotificationCenterDelegate {
    @Published var status = ""
    @Published var settings = Settings.load() { didSet { settings.save() } }
    @Published var pending: [ProtoRequest] = []
    @Published var log = ""
    @Published var focused: String?
    @Published var hideAfterAnswer = true
    @Published var tokenIDs: [String] = []
    /// Which items to publish: secd rejects the whole set when one item is bad.
    private var notified: Set<String> = []
    @Published var itemSet: ItemSet = .certificate
    @Published var setConstraints = false

    override init() {
        super.init()
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound]) { ok, err in
            Log.write("app", "notification authorization: \(ok) \(err.map { "\($0)" } ?? "")")
        }
        let approve = UNNotificationAction(identifier: "open", title: "Open", options: .foreground)
        center.setNotificationCategories([UNNotificationCategory(identifier: "ctk-proto.request", actions: [approve], intentIdentifiers: [])])
        Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        refresh()
    }

    func refresh() {
        #if os(iOS)
        // Nothing else may query tokens while an NFC session is open.
        if nfcSession != nil || nfcStarting { return }
        #endif
        pending = Store.pending()
        if settings.appNotifies == true { notifyNew() }
        log = Log.read()
        tokenIDs = TKTokenWatcher().tokenIDs
        let configured = TKTokenDriver.Configuration.driverConfigurations[Proto.classID]?.tokenConfigurations[Proto.instanceID] != nil
        let keys = [Proto.certObject, Proto.bareObject].map { "\($0): \(Keys.privateKey($0) == nil ? "missing" : "ok")" }
        status = "class \(Proto.classID)\ntoken configured: \(configured)\n" + keys.joined(separator: ", ")
    }

    private func notifyNew() {
        for r in pending where notified.insert(r.id).inserted {
            let c = UNMutableNotificationContent()
            c.title = "Approve a keychain request (from the app)"
            c.body = "\(r.op) with \(r.object)"
            c.userInfo = ["id": r.id]
            c.categoryIdentifier = "ctk-proto.request"
            c.sound = .default
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: r.id, content: c, trigger: nil)) { err in
                Log.write("app", "app notification added: \(err.map { "\($0)" } ?? "ok")")
            }
        }
    }

    // MARK: setup

    func setUp() {
        do {
            let (certKey, cert) = try importTestIdentity()
            try Keys.store(certKey, object: Proto.certObject)
            let bare = try Keys.generate(object: Proto.bareObject)
            try storeBiometricItem()
            try registerToken(cert: cert, bare: bare)
            Log.write("app", "set up: keys stored, configuration written (items=\(itemSet.rawValue) constraints=\(setConstraints))")
            // Writing the configuration says nothing about the keychain: look for the items.
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.checkPublished() }
        } catch {
            Log.write("app", "set up failed: \(error)")
        }
        refresh()
    }

    /// Put the pinned root where the extension can read it, then hold a 3 s request from the app: this
    /// is also where the system asks for local network access, if it does.
    func tryLongPoll() {
        do {
            guard let u = Bundle.main.url(forResource: "longpoll-root", withExtension: "der") else {
                throw err("longpoll-root.der missing: run make-longpoll-cert.sh and xcodegen, then rebuild")
            }
            try Data(contentsOf: u).write(to: LongPoll.rootFile, options: [.atomic, .untilFirstUnlock])
        } catch {
            Log.write("app", "longpoll FAILED: \(error.localizedDescription)")
            return
        }
        let host = settings.holdHost ?? ""
        DispatchQueue.global().async {
            do {
                let r = try LongPoll.hold(host: host, port: 8444, secs: 3) { Log.write("app", "longpoll: \($0)") }
                Log.write("app", "longpoll ok: \(r)")
            } catch {
                Log.write("app", "longpoll FAILED: \(error.localizedDescription)")
            }
        }
    }

    /// Make the Enclave key and try it from the app first, so a later failure is the extension's.
    func makeEnclaveKey() {
        do {
            try Keys.makeEnclaveKey()
            Log.write("app", "enclave: key made; \(try Keys.tryEnclaveKey())")
        } catch {
            Log.write("app", "enclave FAILED: \(error.localizedDescription)")
        }
        refresh()
    }

    /// Are this token's keys really in the keychain?
    func checkPublished() {
        var q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrAccessGroup as String: kSecAttrAccessGroupToken,
            kSecAttrTokenID as String: "\(Proto.classID):\(Proto.instanceID)",
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ]
        #if os(macOS)
        q[kSecUseDataProtectionKeychain as String] = true
        #endif
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        let configs = TKTokenDriver.Configuration.driverConfigurations
        for (cls, d) in configs {
            for (inst, c) in d.tokenConfigurations {
                Log.write("app", "configuration \(cls):\(inst) items=\(c.keychainItems.map { "\($0.objectID) constraints=\($0.constraints?.count ?? 0)" })")
            }
        }
        Log.write("app", "watcher tokens: \(TKTokenWatcher().tokenIDs.filter { $0.contains("ctk-proto") })")
        let labels = ((out as? [[String: Any]]) ?? []).map { $0[kSecAttrLabel as String] as? String ?? "?" }
        Log.write("app", "published keys: status \(st) \(labels)")
        refresh()
    }

    func removeToken() {
        TKTokenDriver.Configuration.driverConfigurations[Proto.classID]?.removeTokenConfiguration(for: Proto.instanceID)
        Log.write("app", "token configuration removed")
        refresh()
    }

    /// `make-test-identity.sh` writes App/Resources/proto.p12 (EC P-256, self-signed, password
    /// `ctk-proto`). The key is re-created from its bytes so it lands in the data-protection keychain.
    private func importTestIdentity() throws -> (SecKey, SecCertificate) {
        guard let url = Bundle.main.url(forResource: "proto", withExtension: "p12") else {
            throw err("proto.p12 missing: run make-test-identity.sh, then rebuild")
        }
        var opts: [String: Any] = [kSecImportExportPassphrase as String: "ctk-proto"]
        #if os(macOS)
        if #available(macOS 15.0, *) { opts[kSecImportToMemoryOnly as String] = true }
        #endif
        var items: CFArray?
        let st = SecPKCS12Import(try Data(contentsOf: url) as CFData, opts as CFDictionary, &items)
        guard st == errSecSuccess, let first = (items as? [[String: Any]])?.first,
              let idRef = first[kSecImportItemIdentity as String] else { throw err("PKCS#12 import: \(st)") }
        let identity = idRef as! SecIdentity
        var key: SecKey?, cert: SecCertificate?
        SecIdentityCopyPrivateKey(identity, &key)
        SecIdentityCopyCertificate(identity, &cert)
        guard let k = key, let c = cert else { throw err("identity without key or certificate") }
        var e: Unmanaged<CFError>?
        guard let bytes = SecKeyCopyExternalRepresentation(k, &e) as Data?,
              let copy = SecKeyCreateWithData(bytes as CFData, [
                  kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                  kSecAttrKeyClass: kSecAttrKeyClassPrivate,
              ] as CFDictionary, &e) else { throw e!.takeRetainedValue() as Error }
        return (copy, c)
    }

    private func registerToken(cert: SecCertificate, bare: SecKey) throws {
        guard let driver = TKTokenDriver.Configuration.driverConfigurations[Proto.classID] else {
            throw err("no driver configuration for \(Proto.classID): is the extension embedded and the app installed?")
        }
        let cfg = driver.addTokenConfiguration(for: Proto.instanceID)
        // The key with a certificate: an identity.
        guard let certItem = TKTokenKeychainCertificate(certificate: cert, objectID: Proto.certObject),
              let certKey = TKTokenKeychainKey(certificate: cert, objectID: Proto.certObject) else {
            throw err("could not make keychain items from the certificate")
        }
        certKey.label = "CTK proto (certificate)"
        certKey.canSign = true
        certKey.canPerformKeyExchange = true
        // P4: the key without a certificate, every property set by hand.
        guard let bareKey = TKTokenKeychainKey(certificate: nil, objectID: Proto.bareObject),
              let pub = SecKeyCopyPublicKey(bare),
              let raw = SecKeyCopyExternalRepresentation(pub, nil) as Data? else { throw err("bare key setup") }
        bareKey.label = "CTK proto (bare)"
        bareKey.keyType = kSecAttrKeyTypeECSECPrimeRandom as String
        bareKey.keySizeInBits = 256
        bareKey.publicKeyData = raw
        bareKey.publicKeyHash = Data(Insecure.SHA1.hash(data: raw))
        bareKey.canSign = true
        bareKey.canPerformKeyExchange = true
        if setConstraints {
            let c: [NSNumber: Any] = [
                NSNumber(value: TKTokenOperation.signData.rawValue): true,
                NSNumber(value: TKTokenOperation.performKeyExchange.rawValue): true,
            ]
            certKey.constraints = c
            bareKey.constraints = c
        }
        switch itemSet {
        case .certificate: cfg.keychainItems = [certItem, certKey]
        case .bare: cfg.keychainItems = [bareKey]
        case .both: cfg.keychainItems = [certItem, certKey, bareKey]
        }
    }

    private func storeBiometricItem() throws {
        SecItemDelete(Keys.biometricQuery() as CFDictionary)
        var e: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, &e) else {
            throw e!.takeRetainedValue() as Error
        }
        var q = Keys.biometricQuery()
        q[kSecValueData as String] = Data("prototype".utf8)
        q[kSecAttrAccessControl as String] = ac
        let st = SecItemAdd(q as CFDictionary, nil)
        Log.write("app", "biometric item stored: \(st)")
    }

    // MARK: answering

    func answer(_ r: ProtoRequest, approve: Bool) {
        if approve {
            do {
                let out = try Keys.perform(r)
                Store.answer(r.id, ProtoResponse(approved: true, result: out, answered: Date()))
                Log.write("app", "approved \(r.id.prefix(12)) after \(String(format: "%.1f", Date().timeIntervalSince(r.created))) s")
            } catch {
                Store.answer(r.id, ProtoResponse(approved: false, result: nil, answered: Date()))
                Log.write("app", "operation failed: \(error)")
            }
        } else {
            Store.answer(r.id, ProtoResponse(approved: false, result: nil, answered: Date()))
            Log.write("app", "denied \(r.id.prefix(12))")
        }
        refresh()
        #if os(macOS)
        // P7: put the calling app back in front.
        if hideAfterAnswer { NSApp.hide(nil) }
        #endif
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler done: @escaping () -> Void) {
        let id = response.notification.request.content.userInfo["id"] as? String
        Log.write("app", "notification opened: \(id?.prefix(12) ?? "-")")
        Task { @MainActor in
            self.focused = id
            self.refresh()
            #if os(macOS)
            NSApp.activate(ignoringOtherApps: true)
            #endif
        }
        done()
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent n: UNNotification, withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void) {
        done([.banner, .sound])
    }

    // MARK: iOS 26 NFC smart card (optional; Brian runs it)

    #if os(iOS)
    /// Held so it can be ended: the system UI stays up otherwise.
    private var nfcSession: Any?
    private var nfcStarting = false
    /// Tokens that appeared during the last read: the only ones offered for registering.
    @Published var justRead: [String] = []

    @available(iOS 26.0, *)
    func createNFCSlot() {
        guard let mgr = TKSmartCardSlotManager.default else { Log.write("app", "nfc: no slot manager"); return }
        guard mgr.isNFCSupported() else { Log.write("app", "nfc: not supported here"); return }
        guard nfcSession == nil, !nfcStarting else { Log.write("app", "nfc: a session is already open"); return }
        nfcStarting = true
        let before = Set(cardTokens)
        let names = Set(mgr.slotNames)
        Log.write("app", "nfc: creating slot; \(before.count) other token(s) already present")
        mgr.createNFCSlot(message: "Hold your YubiKey to the iPhone (read only)") { session, error in
            Log.write("app", "nfc: session=\(session == nil ? "none" : "ok") error=\(error.map { "\($0)" } ?? "-")")
            Task { @MainActor in
                self.nfcSession = session
                self.nfcStarting = false
                guard let session else { self.refresh(); return }
                let slotName = session.slotName
                Log.write("app", "nfc: slot name \(slotName == nil ? "none" : "given"), new slots \(Set(mgr.slotNames).subtracting(names).count)")
                var slot: TKSmartCardSlot?
                var last = ""
                // Until a token appears that wasn't there before, or 40 s.
                for i in 1...40 {
                    try? await Task.sleep(for: .seconds(1))
                    guard self.nfcSession != nil else { return }
                    // The slot's own state only: no session with the card, so no commands from here.
                    if slot == nil, let n = session.slotName { slot = mgr.slotNamed(n) }
                    let now: String
                    switch slot?.state {
                    case .missing?: now = "missing"
                    case .empty?: now = "empty"
                    case .probing?: now = "probing"
                    case .muteCard?: now = "card present but not answering"
                    case .validCard?: now = "valid card"
                    default: now = slot == nil ? "no slot" : "other"
                    }
                    if now != last { Log.write("app", "nfc: slot \(now) after \(i) s"); last = now }
                    if now == "missing" { Log.write("app", "nfc: the system removed the slot"); break }
                    // Only ask for tokens once there is a card, or at the end.
                    guard now == "valid card" || i == 40 else { continue }
                    let new = Set(self.cardTokens).subtracting(before)
                    if !new.isEmpty || i == 40 {
                        self.justRead = Array(new)
                        Log.write("app", "nfc: \(new.count) new card token(s) after \(i) s")
                        break
                    }
                }
                self.endNFCSlot()
            }
        }
    }

    @available(iOS 26.0, *)
    func endNFCSlot() {
        (nfcSession as? TKSmartCardSlotNFCSession)?.end()
        nfcSession = nil
        Log.write("app", "nfc: session ended")
        refresh()
    }

    /// Tokens that aren't the prototype's own or the system's.
    var cardTokens: [String] {
        TKTokenWatcher().tokenIDs.filter { !$0.contains("ctk-proto") && !$0.contains("setoken") && !$0.contains("ctkcard") }
    }

    @available(iOS 26.0, *)
    var registered: [String] { TKSmartCardTokenRegistrationManager.default.registeredSmartCardTokens }

    @available(iOS 26.0, *)
    func register(_ tokenID: String) {
        // One another app registered is left alone, here and when undoing.
        guard !registered.contains(tokenID) else { Log.write("app", "nfc: already registered, not by this button; left alone"); return }
        do {
            UserDefaults.standard.set(mine + [tokenID], forKey: "nfc-registered")
            try TKSmartCardTokenRegistrationManager.default.registerSmartCard(tokenID: tokenID, promptMessage: "Hold your YubiKey to the iPhone (prototype)")
            Log.write("app", "nfc: registered; \(registered.count) card(s) registered now")
        } catch {
            Log.write("app", "nfc: register failed: \(error)")
        }
        refresh()
    }

    /// Cards this prototype registered.
    private var mine: [String] { UserDefaults.standard.stringArray(forKey: "nfc-registered") ?? [] }

    @available(iOS 26.0, *)
    func unregisterMine() {
        for t in mine where registered.contains(t) {
            do { try TKSmartCardTokenRegistrationManager.default.unregisterSmartCard(tokenID: t) } catch {
                Log.write("app", "nfc: unregister failed: \(error)")
            }
        }
        let left = mine.filter { registered.contains($0) }
        UserDefaults.standard.set(left, forKey: "nfc-registered")
        Log.write("app", "nfc: \(left.count) of this prototype's cards still registered, \(registered.count) in all")
        refresh()
    }

    /// Attributes of card keys and certificates only: no references, so nothing can be used.
    /// Token ids are left out of the log: they identify the card.
    func listCardKeys() {
        for (name, cls) in [("keys", kSecClassKey), ("certificates", kSecClassCertificate)] {
            let q: [String: Any] = [
                kSecClass as String: cls,
                kSecAttrAccessGroup as String: kSecAttrAccessGroupToken,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecReturnAttributes as String: true,
            ]
            var out: CFTypeRef?
            let st = SecItemCopyMatching(q as CFDictionary, &out)
            let items = ((out as? [[String: Any]]) ?? []).filter {
                let t = $0[kSecAttrTokenID as String] as? String ?? ""
                return !t.isEmpty && !t.contains("ctk-proto") && !t.contains("setoken") && !t.contains("ctkcard")
            }
            let lines = items.map { "\($0[kSecAttrLabel as String] as? String ?? "?") \($0[kSecAttrKeySizeInBits as String] ?? "")" }
            Log.write("app", "nfc: card \(name): status \(st), \(items.count): \(lines)")
        }
    }
    #endif

    private func err(_ s: String) -> Error { NSError(domain: "ctk-proto", code: 0, userInfo: [NSLocalizedDescriptionKey: s]) }
}

struct ContentView: View {
    @EnvironmentObject var model: Model
    var body: some View {
        NavigationStack {
            Form {
                Section("Setup") {
                    Text(model.status).font(.caption.monospaced())
                    Picker("Items", selection: $model.itemSet) {
                        ForEach(ItemSet.allCases) { Text($0.rawValue).tag($0) }
                    }
                    Toggle("Set operation constraints", isOn: $model.setConstraints)
                    Button("Set up keys and token") { model.setUp() }
                    Button("Make Secure Enclave client key") { model.makeEnclaveKey() }
                    Button("Remove token", role: .destructive) { model.removeToken() }
                }
                Section("Extension") {
                    Picker("Mode", selection: $model.settings.mode) {
                        ForEach(Mode.allCases) { Text($0.rawValue).tag($0) }
                    }
                    Stepper("Wait \(Int(model.settings.waitSecs)) s", value: $model.settings.waitSecs, in: 5...600, step: 5)
                    Stepper("Immediate delay \(Int(model.settings.immediateDelaySecs)) s", value: $model.settings.immediateDelaySecs, in: 0...600, step: 5)
                    TextField("Network URL", text: $model.settings.url)
                    TextField("Long-poll server address", text: Binding(
                        get: { model.settings.holdHost ?? "" },
                        set: { model.settings.holdHost = $0 }))
                    Button("Copy long-poll root and test from the app") { model.tryLongPoll() }
                    #if os(macOS)
                    Toggle("Hide after answering (P7)", isOn: $model.hideAfterAnswer)
                    Toggle("App posts the notification", isOn: Binding(
                        get: { model.settings.appNotifies == true },
                        set: { model.settings.appNotifies = $0 }))
                    #endif
                }
                Section("Pending requests") {
                    if model.pending.isEmpty { Text("None").foregroundStyle(.secondary) }
                    ForEach(model.pending, id: \.id) { r in
                        VStack(alignment: .leading) {
                            Text("\(r.op) · \(r.object)").font(.headline)
                            Text(r.algorithm).font(.caption)
                            Text("input \(r.input.count) B, sha256 \(sha256Hex(r.input).prefix(16))…").font(.caption.monospaced())
                            HStack {
                                Button("Approve") { model.answer(r, approve: true) }.buttonStyle(.borderedProminent)
                                Button("Deny", role: .destructive) { model.answer(r, approve: false) }
                            }
                        }
                        .listRowBackground(model.focused == r.id ? Color.yellow.opacity(0.2) : nil)
                    }
                }
                #if os(iOS)
                if #available(iOS 26.0, *) {
                    Section("iOS 26 NFC smart card (reads a YubiKey; Brian runs it)") {
                        Button("1. Create NFC slot and read the card") { model.createNFCSlot() }
                        Button("2. List the card's keys (no card needed)") { model.listCardKeys() }
                        ForEach(model.justRead, id: \.self) { t in
                            Button("3. Register the card just read") { model.register(t) }
                        }
                        Button("End NFC session") { model.endNFCSlot() }
                        Button("4. Unregister what this prototype registered", role: .destructive) { model.unregisterMine() }
                    }
                }
                #endif
                Section("Log") {
                    Button("Clear log") { Log.clear(); model.refresh() }
                    ShareLink("Copy or share log", item: model.log)
                    Text(model.log.split(separator: "\n").suffix(80).joined(separator: "\n"))
                        .font(.system(size: 10).monospaced())
                        .textSelection(.enabled)
                }
            }
            .navigationTitle("CTK Proto")
        }
    }
}
