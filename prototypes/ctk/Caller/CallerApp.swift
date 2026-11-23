// A stand-in third-party app: finds the token's keys through the keychain and uses them like any
// keychain caller would, timing each call and checking the result.

import CryptoKit
import Security
import SwiftUI
#if os(iOS)
import UIKit
#endif

@main
struct CallerApp: App {
    @StateObject private var m = CallerModel()
    var body: some Scene { WindowGroup { CallerView().environmentObject(m) } }
}

struct TokenKey: Identifiable, Hashable {
    let id: String
    let label: String
    let tokenID: String
    let ref: SecKey
}

enum Op: String, CaseIterable, Identifiable {
    case signMessage = "sign: ecdsaSignatureMessageX962SHA256"
    case signDigest = "sign: ecdsaSignatureDigestX962SHA256 (hash first)"
    case signRFC4754 = "sign: ecdsaSignatureDigestRFC4754 (hash first)"
    case keyExchange = "keyExchange: ecdhKeyExchangeStandard"
    var id: String { rawValue }
}

@MainActor
final class CallerModel: ObservableObject {
    @Published var keys: [TokenKey] = []
    @Published var selected: String?
    @Published var op: Op = .signMessage
    @Published var delay: Double = 20
    @Published var lines: [String] = []

    func say(_ s: String) {
        let line = "\(ISO8601DateFormatter().string(from: Date())) \(s)"
        lines.append(line)
        NSLog("ctk-caller %@", s)
    }

    /// Try every way a caller might look for token items, and say what each one finds.
    static func variants(_ cls: CFString) -> [(String, [String: Any])] {
        let base: [String: Any] = [
            kSecClass as String: cls,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true,
        ]
        let token: [String: Any] = [kSecAttrAccessGroup as String: kSecAttrAccessGroupToken]
        var out = [("plain", base), ("token group", base.merging(token) { $1 })]
        #if os(macOS)
        let dp: [String: Any] = [kSecUseDataProtectionKeychain as String: true]
        out += [("data protection", base.merging(dp) { $1 }),
                ("data protection + token group", base.merging(dp) { $1 }.merging(token) { $1 })]
        #endif
        return out
    }

    func load() {
        var found: [String: TokenKey] = [:]
        for (cname, cls) in [("keys", kSecClassKey), ("identities", kSecClassIdentity)] {
            for (name, q) in Self.variants(cls) {
                var out: CFTypeRef?
                let st = SecItemCopyMatching(q as CFDictionary, &out)
                let items = ((out as? [[String: Any]]) ?? []).filter { $0[kSecAttrTokenID as String] != nil }
                let names = items.map { "\($0[kSecAttrLabel as String] as? String ?? "?") [\($0[kSecAttrTokenID as String] as? String ?? "?")]" }
                say("\(cname), \(name): status \(st), token items \(names)")
                guard cls == kSecClassKey else { continue }
                for a in items {
                    guard let ref = a[kSecValueRef as String], CFGetTypeID(ref as CFTypeRef) == SecKeyGetTypeID() else { continue }
                    let tid = a[kSecAttrTokenID as String] as? String ?? "?"
                    let label = a[kSecAttrLabel as String] as? String ?? "(no label)"
                    // Only the prototype's token: never offer a real card's keys.
                    guard tid.contains("ctk-proto") else { continue }
                    let id = "\(tid)/\(label)"
                    found[id] = TokenKey(id: id, label: label, tokenID: tid, ref: ref as! SecKey)
                }
            }
        }
        keys = found.values.sorted { $0.id < $1.id }
        if selected == nil { selected = keys.first?.id }
    }

    func run(after: Double) {
        guard let k = keys.first(where: { $0.id == selected }) else { say("no key selected"); return }
        let op = self.op
        #if os(iOS)
        var task = UIBackgroundTaskIdentifier.invalid
        task = UIApplication.shared.beginBackgroundTask(withName: "ctk-caller") {
            NSLog("ctk-caller background task expired")
            UIApplication.shared.endBackgroundTask(task)
        }
        #endif
        say("\(op.rawValue) with \(k.label) in \(Int(after)) s")
        DispatchQueue.global().asyncAfter(deadline: .now() + after) {
            let line = Self.perform(op, k.ref)
            Task { @MainActor in
                self.say(line)
                #if os(iOS)
                UIApplication.shared.endBackgroundTask(task)
                #endif
            }
        }
    }

    nonisolated static func perform(_ op: Op, _ key: SecKey) -> String {
        let message = Data("prototype message \(Date())".utf8)
        let t0 = Date()
        var e: Unmanaged<CFError>?
        func took() -> String { String(format: "%.1f s", Date().timeIntervalSince(t0)) }
        guard let pub = SecKeyCopyPublicKey(key) else { return "no public key" }
        switch op {
        case .keyExchange:
            let mine = P256.KeyAgreement.PrivateKey()
            guard let peer = SecKeyCreateWithData(mine.publicKey.x963Representation as CFData, [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic,
            ] as CFDictionary, &e) else { return "peer key: \(e!.takeRetainedValue())" }
            guard let secret = SecKeyCopyKeyExchangeResult(key, .ecdhKeyExchangeStandard, peer, [:] as CFDictionary, &e) as Data? else {
                return "keyExchange failed after \(took()): \(e!.takeRetainedValue())"
            }
            let theirs = SecKeyCopyExternalRepresentation(pub, nil) as Data? ?? Data()
            let expect = (try? mine.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: theirs)))
                .map { $0.withUnsafeBytes { Data($0) } }
            return "keyExchange ok after \(took()), matches=\(expect == secret)"
        default:
            let (alg, input): (SecKeyAlgorithm, Data) = {
                switch op {
                case .signMessage: return (.ecdsaSignatureMessageX962SHA256, message)
                case .signDigest: return (.ecdsaSignatureDigestX962SHA256, Data(SHA256.hash(data: message)))
                default: return (.ecdsaSignatureDigestRFC4754, Data(SHA256.hash(data: message)))
                }
            }()
            let supported = SecKeyIsAlgorithmSupported(key, .sign, alg)
            guard let sig = SecKeyCreateSignature(key, alg, input as CFData, &e) as Data? else {
                return "sign failed after \(took()) (supported=\(supported)): \(e!.takeRetainedValue())"
            }
            let ok = SecKeyVerifySignature(pub, alg, input as CFData, sig as CFData, nil)
            return "sign ok after \(took()), \(sig.count) B, verifies=\(ok), supported=\(supported)"
        }
    }
}

struct CallerView: View {
    @EnvironmentObject var m: CallerModel
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Button("Find token keys") { m.load() }
                    Picker("Key", selection: $m.selected) {
                        ForEach(m.keys) { Text($0.label).tag(Optional($0.id)) }
                    }
                    Picker("Operation", selection: $m.op) {
                        ForEach(Op.allCases) { Text($0.rawValue).tag($0) }
                    }
                    Button("Run now") { m.run(after: 0) }
                    Stepper("Delay \(Int(m.delay)) s", value: $m.delay, in: 5...120, step: 5)
                    Button("Run after delay (then background or lock)") { m.run(after: m.delay) }
                }
                Section("Results") {
                    ForEach(Array(m.lines.enumerated().reversed()), id: \.offset) { Text($0.element).font(.caption.monospaced()) }
                }
            }
            .navigationTitle("CTK Caller")
        }
    }
}
