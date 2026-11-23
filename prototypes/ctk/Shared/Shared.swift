// Shared by the prototype app and its token extension: identifiers, the call log, settings, the
// request store and the software keys that stand in for the YubiKey.
//
// Prototype only. The real design stores signed requests and sealed responses (docs/cryptotokenkit.md,
// "The shared store"); here a response carries the plain result, because the keys are throwaway.

import CryptoKit
import Foundation
import os
import Security

enum Proto {
    static func info(_ key: String) -> String {
        Bundle.main.object(forInfoDictionaryKey: key) as? String ?? "missing-\(key)"
    }
    static var group: String { info("ProtoGroup") }
    static var keychainGroup: String { info("ProtoKeychainGroup") }
    static var classID: String { info("ProtoClassID") }
    static let instanceID = "ctk-proto"

    /// Token object ids: one key with a certificate (from the bundled test identity), one without.
    static let certObject = "with-cert"
    static let bareObject = "bare"

    static var container: URL {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
            ?? FileManager.default.temporaryDirectory
    }
}

// MARK: - Settings (a JSON file in the App Group container, written by the app)

enum Mode: String, Codable, CaseIterable, Identifiable {
    /// P1: post a notification, wait for the app to answer through the store.
    case handoff
    /// Baseline: sign inside the extension at once with the shared software key.
    case immediate
    /// P6: keep an HTTPS request going from the extension for the wait, then sign in the extension.
    case network
    /// Face ID / Touch ID from inside the extension (reading a biometric-protected item), then sign.
    case biometric
    /// The client identity key: sign a test message with a Secure Enclave key the app made, from the
    /// extension and with no biometric, then answer with the software key.
    case enclave
    var id: String { rawValue }
}

struct Settings: Codable, Equatable {
    var mode: Mode = .handoff
    /// How long the extension waits for an answer (handoff) or keeps the network busy (network).
    var waitSecs: Double = 100
    /// Polled by the network mode.
    var url: String = "https://www.apple.com/library/test/success.html"
    /// Delay before answering in immediate mode (to measure caller limits without a person).
    var immediateDelaySecs: Double = 0
    /// The running app posts the notification instead of the extension (the Mac click problem).
    /// Optional so an older settings file still loads.
    var appNotifies: Bool?

    static var file: URL { Proto.container.appendingPathComponent("settings.json") }
    static func load() -> Settings {
        (try? JSONDecoder().decode(Settings.self, from: Data(contentsOf: file))) ?? Settings()
    }
    func save() {
        try? JSONEncoder().encode(self).write(to: Settings.file, options: [.atomic, .untilFirstUnlock])
    }
}

// MARK: - Call log (P2, P3): one line per event, readable by the app

enum Log {
    static var file: URL { Proto.container.appendingPathComponent("calls.log") }
    static func write(_ who: String, _ msg: String) {
        let line = "\(ISO8601DateFormatter.ms.string(from: Date())) [\(who) \(ProcessInfo.processInfo.processIdentifier)] \(msg)\n"
        guard let data = line.data(using: .utf8) else { return }
        if let h = try? FileHandle(forWritingTo: file) {
            h.seekToEndOfFile()
            h.write(data)
            try? h.close()
        } else {
            try? data.write(to: file, options: .untilFirstUnlock)
        }
        // Public on purpose: prototype data only (hashes, algorithms, timings).
        Logger(subsystem: "ctk-proto", category: who).notice("\(msg, privacy: .public)")
    }
    static func read() -> String { (try? String(contentsOf: file, encoding: .utf8)) ?? "" }
    static func clear() { try? FileManager.default.removeItem(at: file) }
}

extension ISO8601DateFormatter {
    static let ms: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
}

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
func sha256Hex(_ d: Data) -> String { hex(Data(SHA256.hash(data: d))) }

extension Data.WritingOptions {
    #if os(iOS)
    static let untilFirstUnlock: Data.WritingOptions = .completeFileProtectionUntilFirstUserAuthentication
    #else
    static let untilFirstUnlock: Data.WritingOptions = []
    #endif
}

// MARK: - Request store (the hand-off): one record per (object, algorithm, input)

struct ProtoRequest: Codable {
    var id: String
    var op: String          // "sign" or "keyExchange"
    var object: String
    var algorithm: String   // SecKeyAlgorithm raw value
    var input: Data
    var created: Date
}

struct ProtoResponse: Codable {
    var approved: Bool
    var result: Data?
    var answered: Date
}

enum Store {
    static var dir: URL {
        let d = Proto.container.appendingPathComponent("requests", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }
    static func id(object: String, algorithm: String, input: Data) -> String {
        sha256Hex(Data((object + "\n" + algorithm + "\n").utf8) + input)
    }
    static func requestURL(_ id: String) -> URL { dir.appendingPathComponent("\(id).req") }
    static func responseURL(_ id: String) -> URL { dir.appendingPathComponent("\(id).resp") }

    /// Exclusive create: true only for the call that made the record, false if it already exists.
    /// Any other failure (no access to the container) throws.
    static func create(_ r: ProtoRequest) throws -> Bool {
        let d = try JSONEncoder().encode(r)
        do {
            try d.write(to: requestURL(r.id), options: [.withoutOverwriting, .untilFirstUnlock])
            return true
        } catch let e as CocoaError where e.code == .fileWriteFileExists {
            return false
        }
    }
    static func request(_ id: String) -> ProtoRequest? {
        (try? Data(contentsOf: requestURL(id))).flatMap { try? JSONDecoder().decode(ProtoRequest.self, from: $0) }
    }
    static func pending() -> [ProtoRequest] {
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        return files.filter { $0.pathExtension == "req" }
            .compactMap { try? JSONDecoder().decode(ProtoRequest.self, from: Data(contentsOf: $0)) }
            .filter { response($0.id) == nil }
            .sorted { $0.created < $1.created }
    }
    static func answer(_ id: String, _ r: ProtoResponse) {
        if let d = try? JSONEncoder().encode(r) {
            try? d.write(to: responseURL(id), options: [.atomic, .untilFirstUnlock])
        }
    }
    static func response(_ id: String) -> ProtoResponse? {
        (try? Data(contentsOf: responseURL(id))).flatMap { try? JSONDecoder().decode(ProtoResponse.self, from: $0) }
    }
    static func remove(_ id: String) {
        try? FileManager.default.removeItem(at: requestURL(id))
        try? FileManager.default.removeItem(at: responseURL(id))
    }
    /// Drop records older than `secs`.
    static func prune(olderThan secs: Double) {
        for r in (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.creationDateKey])) ?? [] {
            let made = (try? r.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? Date()
            if Date().timeIntervalSince(made) > secs { try? FileManager.default.removeItem(at: r) }
        }
    }
}

// MARK: - Software keys (shared keychain group), standing in for the YubiKey

enum Keys {
    static func tag(_ object: String) -> Data { Data("ctk-proto.\(object)".utf8) }

    static func base(_ object: String) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag(object),
            kSecAttrAccessGroup as String: Proto.keychainGroup,
        ]
        #if os(macOS)
        q[kSecUseDataProtectionKeychain as String] = true
        #endif
        return q
    }

    static func privateKey(_ object: String) -> SecKey? {
        var q = base(object)
        q[kSecReturnRef as String] = true
        q[kSecAttrKeyClass as String] = kSecAttrKeyClassPrivate
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return (out as! SecKey)
    }

    /// Store a private key under `object`, readable after first unlock by the app and the extension.
    static func store(_ key: SecKey, object: String) throws {
        SecItemDelete(base(object) as CFDictionary)
        var q = base(object)
        q[kSecValueRef as String] = key
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let st = SecItemAdd(q as CFDictionary, nil)
        guard st == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(st)) }
    }

    static func generate(object: String) throws -> SecKey {
        var err: Unmanaged<CFError>?
        guard let k = SecKeyCreateRandomKey([
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
        ] as CFDictionary, &err) else { throw err!.takeRetainedValue() as Error }
        try store(k, object: object)
        return k
    }

    /// Run the operation with the software key: what the YubiKey would do after the PIN.
    static func perform(_ r: ProtoRequest) throws -> Data {
        guard let key = privateKey(r.object) else { throw NSError(domain: "ctk-proto", code: 1, userInfo: [NSLocalizedDescriptionKey: "no key for \(r.object)"]) }
        let alg = SecKeyAlgorithm(rawValue: r.algorithm as CFString)
        var err: Unmanaged<CFError>?
        let out: CFData?
        if r.op == "keyExchange" {
            guard let peer = SecKeyCreateWithData(r.input as CFData, [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass: kSecAttrKeyClassPublic,
            ] as CFDictionary, &err) else { throw err!.takeRetainedValue() as Error }
            out = SecKeyCopyKeyExchangeResult(key, alg, peer, [:] as CFDictionary, &err)
        } else {
            out = SecKeyCreateSignature(key, alg, r.input as CFData, &err)
        }
        guard let d = out else { throw err!.takeRetainedValue() as Error }
        return d as Data
    }

    // MARK: Secure Enclave client key (made by the app, used by the extension)

    static let enclaveObject = "enclave-client"

    static func makeEnclaveKey() throws {
        SecItemDelete(base(enclaveObject) as CFDictionary)
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &err) else {
            throw err!.takeRetainedValue() as Error
        }
        var attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag(enclaveObject),
                kSecAttrAccessGroup as String: Proto.keychainGroup,
                kSecAttrAccessControl as String: ac,
            ] as [String: Any],
        ]
        #if os(macOS)
        attrs[kSecUseDataProtectionKeychain as String] = true
        #endif
        guard SecKeyCreateRandomKey(attrs as CFDictionary, &err) != nil else { throw err!.takeRetainedValue() as Error }
    }

    /// Find the key, sign, verify, and check it is an Enclave key that can't be exported. Throws at
    /// the first step that fails, with that step's status.
    static func tryEnclaveKey() throws -> String {
        func fail(_ s: String) -> Error { NSError(domain: "ctk-proto", code: 2, userInfo: [NSLocalizedDescriptionKey: s]) }
        var q = base(enclaveObject)
        q[kSecAttrKeyClass as String] = kSecAttrKeyClassPrivate
        q[kSecReturnRef as String] = true
        q[kSecReturnAttributes as String] = true
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        guard st == errSecSuccess, let d = out as? [String: Any], let ref = d[kSecValueRef as String] else {
            throw fail("lookup status \(st) \(SecCopyErrorMessageString(st, nil) as String? ?? "")")
        }
        let key = ref as! SecKey
        let token = d[kSecAttrTokenID as String] as? String ?? "none"
        guard token == kSecAttrTokenIDSecureEnclave as String else { throw fail("not an Enclave key: token \(token)") }
        guard SecKeyCopyExternalRepresentation(key, nil) == nil else { throw fail("the private key could be exported") }
        let msg = Data("client request \(Date())".utf8)
        let t0 = Date()
        var err: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, msg as CFData, &err) else {
            throw fail("sign: \(err!.takeRetainedValue())")
        }
        let took = Date().timeIntervalSince(t0)
        guard let pub = SecKeyCopyPublicKey(key),
              SecKeyVerifySignature(pub, .ecdsaSignatureMessageX962SHA256, msg as CFData, sig, nil) else { throw fail("the signature does not verify") }
        return "ok: Enclave key, not exportable, signed and verified in \(String(format: "%.3f", took)) s"
    }

    /// A keychain item that needs Face ID / Touch ID to read: the extension's biometric test.
    static let biometricAccount = "ctk-proto.biometric"
    static func biometricQuery() -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: biometricAccount,
            kSecAttrAccessGroup as String: Proto.keychainGroup,
        ]
        #if os(macOS)
        q[kSecUseDataProtectionKeychain as String] = true
        #endif
        return q
    }
}
