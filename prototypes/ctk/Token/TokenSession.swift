// The prototype's persistent-token extension. It logs every call (P3), then answers in the mode the
// app chose: hand-off to the app (P1, P5), at once, after keeping the network busy (P6), or after
// Face ID / Touch ID from inside the extension.

import CryptoTokenKit
import Foundation
import LocalAuthentication
import Security
import UserNotifications

final class TokenDriver: TKTokenDriver, TKTokenDriverDelegate {
    func tokenDriver(_ driver: TKTokenDriver, tokenFor configuration: TKToken.Configuration) throws -> TKToken {
        Log.write("ext", "tokenFor instance=\(configuration.instanceID)")
        return Token(tokenDriver: self, instanceID: configuration.instanceID)
    }
}

final class Token: TKToken, TKTokenDelegate {
    func createSession(_ token: TKToken) throws -> TKTokenSession {
        let s = TokenSession(token: self)
        Log.write("ext", "createSession \(ObjectIdentifier(s).hashValue)")
        return s
    }
}

/// The EC algorithms the prototype can map a request onto, most specific first.
let candidates: [SecKeyAlgorithm] = [
    .ecdsaSignatureMessageX962SHA256, .ecdsaSignatureMessageX962SHA384, .ecdsaSignatureMessageX962SHA512,
    .ecdsaSignatureMessageX962SHA224, .ecdsaSignatureMessageX962SHA1,
    .ecdsaSignatureDigestX962SHA256, .ecdsaSignatureDigestX962SHA384, .ecdsaSignatureDigestX962SHA512,
    .ecdsaSignatureDigestX962SHA224, .ecdsaSignatureDigestX962SHA1, .ecdsaSignatureDigestX962,
    .ecdsaSignatureDigestRFC4754,
    .ecdhKeyExchangeStandard, .ecdhKeyExchangeCofactor,
    .ecdhKeyExchangeStandardX963SHA256, .ecdhKeyExchangeCofactorX963SHA256,
]

func describe(_ a: TKTokenKeyAlgorithm) -> String {
    let exact = candidates.filter { a.isAlgorithm($0) }.map { $0.rawValue as String }
    let convertible = candidates.filter { a.supportsAlgorithm($0) && !a.isAlgorithm($0) }.map { $0.rawValue as String }
    return "is=\(exact) converts=\(convertible)"
}

final class TokenSession: TKTokenSession, TKTokenSessionDelegate {
    /// Signatures handed out recently, for repeats of the same call (P3).
    private var recent: [String: (Data, Date)] = [:]

    func tokenSession(_ session: TKTokenSession, supports operation: TKTokenOperation, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) -> Bool {
        let ok: Bool
        switch operation {
        case .signData: ok = candidates.prefix(12).contains { algorithm.isAlgorithm($0) }
        case .performKeyExchange: ok = candidates.suffix(4).contains { algorithm.isAlgorithm($0) }
        default: ok = false
        }
        Log.write("ext", "supports op=\(operation.rawValue) key=\(keyObjectID) \(describe(algorithm)) -> \(ok)")
        return ok
    }

    func tokenSession(_ session: TKTokenSession, beginAuthFor operation: TKTokenOperation, constraint: Any) throws -> TKTokenAuthOperation {
        Log.write("ext", "beginAuthFor op=\(operation.rawValue) constraint=\(constraint)")
        return TKTokenAuthOperation()
    }

    func tokenSession(_ session: TKTokenSession, sign dataToSign: Data, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) throws -> Data {
        guard let alg = candidates.prefix(12).first(where: { algorithm.isAlgorithm($0) }) else {
            Log.write("ext", "sign: no algorithm match \(describe(algorithm))")
            throw TKError(.canceledByUser)
        }
        return try handle(op: "sign", object: "\(keyObjectID)", algorithm: alg, input: dataToSign)
    }

    func tokenSession(_ session: TKTokenSession, decrypt ciphertext: Data, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) throws -> Data {
        Log.write("ext", "decrypt key=\(keyObjectID) \(describe(algorithm)) len=\(ciphertext.count) (EC prototype: unsupported)")
        throw TKError(.canceledByUser)
    }

    func tokenSession(_ session: TKTokenSession, performKeyExchange otherPartyPublicKeyData: Data, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm, parameters: TKTokenKeyExchangeParameters) throws -> Data {
        guard let alg = candidates.suffix(4).first(where: { algorithm.isAlgorithm($0) }) else {
            Log.write("ext", "keyExchange: no algorithm match \(describe(algorithm))")
            throw TKError(.canceledByUser)
        }
        return try handle(op: "keyExchange", object: "\(keyObjectID)", algorithm: alg, input: otherPartyPublicKeyData)
    }

    // MARK: -

    private func handle(op: String, object: String, algorithm: SecKeyAlgorithm, input: Data) throws -> Data {
        let settings = Settings.load()
        let id = Store.id(object: object, algorithm: algorithm.rawValue as String, input: input)
        let started = Date()
        Log.write("ext", "\(op) key=\(object) alg=\(algorithm.rawValue) input=\(input.count)B sha256=\(sha256Hex(input).prefix(16)) id=\(id.prefix(12)) mode=\(settings.mode.rawValue)")

        if let (sig, at) = recent[id], Date().timeIntervalSince(at) < 10 {
            Log.write("ext", "repeat within 10 s of an answer: same result")
            return sig
        }
        let req = ProtoRequest(id: id, op: op, object: object, algorithm: algorithm.rawValue as String, input: input, created: Date())

        let result: Data
        switch settings.mode {
        case .handoff:
            result = try handoff(req, settings: settings)
        case .immediate:
            if settings.immediateDelaySecs > 0 {
                Log.write("ext", "immediate: waiting \(settings.immediateDelaySecs) s")
                Thread.sleep(forTimeInterval: settings.immediateDelaySecs)
            }
            result = try Keys.perform(req)
        case .network:
            keepNetworkBusy(settings)
            result = try Keys.perform(req)
        case .biometric:
            try readBiometricItem()
            result = try Keys.perform(req)
        }
        recent[id] = (result, Date())
        Log.write("ext", "\(op) done after \(String(format: "%.1f", Date().timeIntervalSince(started))) s, \(result.count)B")
        return result
    }

    /// P1: notification, then wait for the app's answer in the store.
    private func handoff(_ req: ProtoRequest, settings: Settings) throws -> Data {
        Store.prune(olderThan: settings.waitSecs + 30)
        if Store.create(req) {
            Log.write("ext", "record created, posting notification")
            postNotification(req)
        } else {
            Log.write("ext", "record exists (repeat call): waiting on it")
        }
        let deadline = Date().addingTimeInterval(settings.waitSecs)
        var tick = 0
        while Date() < deadline {
            if let r = Store.response(req.id) {
                Log.write("ext", "answer: approved=\(r.approved)")
                Store.remove(req.id)
                guard r.approved, let d = r.result else { throw TKError(.canceledByUser) }
                return d
            }
            Thread.sleep(forTimeInterval: 0.5)
            tick += 1
            if tick % 20 == 0 { Log.write("ext", "still waiting, \(tick / 2) s") }
        }
        Log.write("ext", "timed out after \(settings.waitSecs) s")
        Store.remove(req.id)
        throw TKError(.canceledByUser)
    }

    private func postNotification(_ req: ProtoRequest) {
        let c = UNMutableNotificationContent()
        c.title = "Approve a keychain request"
        c.body = "\(req.op) with \(req.object), \(req.algorithm)"
        c.userInfo = ["id": req.id]
        c.categoryIdentifier = "ctk-proto.request"
        c.sound = .default
        if #available(iOS 15.0, macOS 12.0, *) { c.interruptionLevel = .timeSensitive }
        let n = UNNotificationRequest(identifier: req.id, content: c, trigger: nil)
        UNUserNotificationCenter.current().add(n) { err in
            Log.write("ext", "notification added: \(err.map { "\($0)" } ?? "ok")")
        }
    }

    /// P6: keep HTTPS requests going for the whole wait.
    private func keepNetworkBusy(_ settings: Settings) {
        guard let url = URL(string: settings.url) else { return }
        let deadline = Date().addingTimeInterval(settings.waitSecs)
        var n = 0
        while Date() < deadline {
            n += 1
            let sem = DispatchSemaphore(value: 0)
            let t0 = Date()
            var status = "?"
            URLSession.shared.dataTask(with: url) { _, resp, err in
                status = err.map { "error \($0.localizedDescription)" } ?? "\((resp as? HTTPURLResponse)?.statusCode ?? 0)"
                sem.signal()
            }.resume()
            _ = sem.wait(timeout: .now() + 30)
            Log.write("ext", "network #\(n): \(status) in \(String(format: "%.2f", Date().timeIntervalSince(t0))) s")
            Thread.sleep(forTimeInterval: 5)
        }
    }

    /// Face ID / Touch ID from inside the extension: read the item the app stored with
    /// `.biometryCurrentSet`.
    private func readBiometricItem() throws {
        var q = Keys.biometricQuery()
        q[kSecReturnData as String] = true
        let ctx = LAContext()
        ctx.localizedReason = "Approve the keychain request (prototype)"
        q[kSecUseAuthenticationContext as String] = ctx
        var out: CFTypeRef?
        let t0 = Date()
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        Log.write("ext", "biometric item read: status \(st) after \(String(format: "%.1f", Date().timeIntervalSince(t0))) s")
        guard st == errSecSuccess else { throw TKError(.canceledByUser) }
    }
}
