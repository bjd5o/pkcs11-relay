// Every PKCS#11 call the sample app makes, written the way a third-party integrator would:
// the standard C API from RelayPKCS11.xcframework, through the function list that
// C_GetFunctionList returns. Nothing here knows about the relay. The provider finds its
// config at ~/Library/Application Support/relay-pkcs11/provider.toml, which on iPadOS is
// inside the app's container (ProviderConfig.swift writes it there).
//
// All calls run on one serial background queue: C_Sign blocks until a person approves the
// request (up to the config's timeout_secs), so it must never run on the main thread.

import CryptoKit
import Foundation
import RelayPKCS11

struct PKCS11Error: Error, CustomStringConvertible {
    let call: String
    let rv: CK_RV

    var description: String {
        "\(call) returned \(Self.name(rv)) (0x\(String(rv, radix: 16)))"
    }

    static func name(_ rv: CK_RV) -> String {
        let names: [(CK_RV, String)] = [
            (CK_RV(CKR_OK), "CKR_OK"),
            (CK_RV(CKR_GENERAL_ERROR), "CKR_GENERAL_ERROR"),
            (CK_RV(CKR_ARGUMENTS_BAD), "CKR_ARGUMENTS_BAD"),
            (CK_RV(CKR_DEVICE_ERROR), "CKR_DEVICE_ERROR"),
            (CK_RV(CKR_FUNCTION_CANCELED), "CKR_FUNCTION_CANCELED"),
            (CK_RV(CKR_FUNCTION_REJECTED), "CKR_FUNCTION_REJECTED (denied)"),
            (CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED), "CKR_KEY_FUNCTION_NOT_PERMITTED"),
            (CK_RV(CKR_KEY_HANDLE_INVALID), "CKR_KEY_HANDLE_INVALID"),
            (CK_RV(CKR_MECHANISM_INVALID), "CKR_MECHANISM_INVALID"),
            (CK_RV(CKR_SLOT_ID_INVALID), "CKR_SLOT_ID_INVALID"),
            (CK_RV(CKR_TOKEN_NOT_PRESENT), "CKR_TOKEN_NOT_PRESENT"),
            (CK_RV(CKR_CRYPTOKI_NOT_INITIALIZED), "CKR_CRYPTOKI_NOT_INITIALIZED"),
        ]
        return names.first { $0.0 == rv }?.1 ?? "CKR_?"
    }
}

/// A private key that can sign, with the public key material read from its public object.
struct SigningKey: Identifiable, Hashable {
    let slot: CK_SLOT_ID
    let token: String
    let label: String
    let ckaID: [UInt8]
    let keyType: CK_KEY_TYPE
    let ecParams: [UInt8]?
    /// DER OCTET STRING around the point, as CKA_EC_POINT holds it.
    let ecPoint: [UInt8]?
    let modulus: [UInt8]?
    let exponent: [UInt8]?

    var id: String { "\(token)-\(label)" }
}

/// How a key signs here: one scheme per key type and curve, and the PKCS#11 mechanisms for it.
enum SignScheme: String {
    case ecdsaP256SHA256 = "ECDSA P-256 SHA-256"
    case ecdsaP384SHA384 = "ECDSA P-384 SHA-384"
    case rsaPKCS1SHA256 = "RSA PKCS#1 v1.5 SHA-256"
    case ed25519 = "Ed25519"

    static let p256OID: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
    static let p384OID: [UInt8] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]

    init?(_ key: SigningKey) {
        switch key.keyType {
        case CK_KEY_TYPE(CKK_EC) where key.ecParams == Self.p256OID: self = .ecdsaP256SHA256
        case CK_KEY_TYPE(CKK_EC) where key.ecParams == Self.p384OID: self = .ecdsaP384SHA384
        case CK_KEY_TYPE(CKK_RSA): self = .rsaPKCS1SHA256
        case CK_KEY_TYPE(CKK_EC_EDWARDS): self = .ed25519
        default: return nil
        }
    }

    /// The mechanisms to try, in order, with the data each one signs. A key may allow only
    /// hash-and-sign or only the raw mechanism over a digest; both give the same signature.
    func attempts(_ message: Data) -> [(CK_MECHANISM_TYPE, String, [UInt8])] {
        switch self {
        case .ecdsaP256SHA256:
            return [(CK_MECHANISM_TYPE(CKM_ECDSA_SHA256), "CKM_ECDSA_SHA256", [UInt8](message)),
                    (CK_MECHANISM_TYPE(CKM_ECDSA), "CKM_ECDSA", Array(SHA256.hash(data: message)))]
        case .ecdsaP384SHA384:
            return [(CK_MECHANISM_TYPE(CKM_ECDSA_SHA384), "CKM_ECDSA_SHA384", [UInt8](message)),
                    (CK_MECHANISM_TYPE(CKM_ECDSA), "CKM_ECDSA", Array(SHA384.hash(data: message)))]
        case .rsaPKCS1SHA256:
            // DigestInfo for SHA-256, then the digest (RFC 8017, 9.2 note 1).
            let prefix: [UInt8] = [0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                                   0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
            return [(CK_MECHANISM_TYPE(CKM_SHA256_RSA_PKCS), "CKM_SHA256_RSA_PKCS", [UInt8](message)),
                    (CK_MECHANISM_TYPE(CKM_RSA_PKCS), "CKM_RSA_PKCS", prefix + Array(SHA256.hash(data: message)))]
        case .ed25519:
            return [(CK_MECHANISM_TYPE(CKM_EDDSA), "CKM_EDDSA", [UInt8](message))]
        }
    }
}

struct SignResult {
    let scheme: SignScheme
    let mechanism: String
    let signature: Data
}

final class PKCS11Module: @unchecked Sendable {
    private let queue = DispatchQueue(label: "pkcs11", qos: .userInitiated)
    /// Touched only on `queue`.
    private var functions: UnsafeMutablePointer<CK_FUNCTION_LIST>?

    /// C_Initialize (after C_Finalize if already started). The provider reads its config now.
    func start() async throws {
        try await onQueue { [self] in
            stopOnQueue()
            var list: UnsafeMutablePointer<CK_FUNCTION_LIST>?
            try check("C_GetFunctionList", C_GetFunctionList(&list))
            guard let list else { throw PKCS11Error(call: "C_GetFunctionList", rv: CK_RV(CKR_GENERAL_ERROR)) }
            var args = CK_C_INITIALIZE_ARGS()
            args.flags = CK_FLAGS(CKF_OS_LOCKING_OK)
            try check("C_Initialize", withUnsafeMutablePointer(to: &args) {
                list.pointee.C_Initialize!(UnsafeMutableRawPointer($0))
            })
            functions = list
        }
    }

    /// C_Finalize, so the next start() reads the config again.
    func stop() async {
        try? await onQueue { [self] in stopOnQueue() }
    }

    /// Every private key that can sign, in every slot with a token (C_GetSlotList,
    /// C_GetTokenInfo, C_FindObjects, C_GetAttributeValue).
    func signingKeys() async throws -> [SigningKey] {
        try await onQueue { [self] in
            let f = try list()
            var count: CK_ULONG = 0
            try check("C_GetSlotList", f.C_GetSlotList!(CK_BBOOL(CK_TRUE), nil, &count))
            var slots = [CK_SLOT_ID](repeating: 0, count: Int(count))
            try check("C_GetSlotList", f.C_GetSlotList!(CK_BBOOL(CK_TRUE), &slots, &count))
            var keys: [SigningKey] = []
            for slot in slots.prefix(Int(count)) {
                var info = CK_TOKEN_INFO()
                try check("C_GetTokenInfo", f.C_GetTokenInfo!(slot, &info))
                let token = withUnsafeBytes(of: info.label) { String(decoding: $0, as: UTF8.self) }
                    .trimmingCharacters(in: .whitespaces)
                let s = try openSession(f, slot)
                defer { _ = f.C_CloseSession!(s) }
                let template = Template()
                    .add(CKA_CLASS, ulong: CK_ULONG(CKO_PRIVATE_KEY))
                    .add(CKA_SIGN, bool: true)
                for key in try find(f, s, template) {
                    let id = attribute(f, s, key, CKA_ID) ?? []
                    let pub = try find(f, s, Template()
                        .add(CKA_CLASS, ulong: CK_ULONG(CKO_PUBLIC_KEY))
                        .add(CKA_ID, id)).first ?? key
                    keys.append(SigningKey(
                        slot: slot,
                        token: token,
                        label: String(decoding: attribute(f, s, key, CKA_LABEL) ?? [], as: UTF8.self),
                        ckaID: id,
                        keyType: ulong(attribute(f, s, key, CKA_KEY_TYPE)) ?? CK_KEY_TYPE.max,
                        ecParams: attribute(f, s, pub, CKA_EC_PARAMS),
                        ecPoint: attribute(f, s, pub, CKA_EC_POINT),
                        modulus: attribute(f, s, pub, CKA_MODULUS),
                        exponent: attribute(f, s, pub, CKA_PUBLIC_EXPONENT)))
                }
            }
            return keys
        }
    }

    /// C_SignInit and C_Sign. Blocks (on the background queue) until the request is approved,
    /// denied or times out.
    func sign(_ key: SigningKey, message: Data) async throws -> SignResult {
        try await onQueue { [self] in
            let f = try list()
            guard let scheme = SignScheme(key) else {
                throw PKCS11Error(call: "key type", rv: CK_RV(CKR_MECHANISM_INVALID))
            }
            let s = try openSession(f, key.slot)
            defer { _ = f.C_CloseSession!(s) }
            guard let handle = try find(f, s, Template()
                .add(CKA_CLASS, ulong: CK_ULONG(CKO_PRIVATE_KEY))
                .add(CKA_ID, key.ckaID)).first
            else { throw PKCS11Error(call: "C_FindObjects", rv: CK_RV(CKR_KEY_HANDLE_INVALID)) }

            let attempts = scheme.attempts(message)
            for (i, (type, name, data)) in attempts.enumerated() {
                var mechanism = CK_MECHANISM(mechanism: type, pParameter: nil, ulParameterLen: 0)
                let rv = f.C_SignInit!(s, &mechanism, handle)
                let refused = rv == CK_RV(CKR_MECHANISM_INVALID) || rv == CK_RV(CKR_KEY_FUNCTION_NOT_PERMITTED)
                if refused && i + 1 < attempts.count { continue }
                try check("C_SignInit(\(name))", rv)
                var input = data
                // Length query first: this is the call that waits for the approval; the second
                // call returns the cached result.
                var length: CK_ULONG = 0
                try check("C_Sign", f.C_Sign!(s, &input, CK_ULONG(input.count), nil, &length))
                var signature = [UInt8](repeating: 0, count: Int(length))
                try check("C_Sign", f.C_Sign!(s, &input, CK_ULONG(input.count), &signature, &length))
                return SignResult(scheme: scheme, mechanism: name, signature: Data(signature.prefix(Int(length))))
            }
            throw PKCS11Error(call: "C_SignInit", rv: CK_RV(CKR_MECHANISM_INVALID))
        }
    }

    // MARK: - Helpers (all on `queue`)

    private func onQueue<T>(_ body: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { c in
            queue.async { c.resume(with: Result { try body() }) }
        }
    }

    private func stopOnQueue() {
        if let f = functions {
            _ = f.pointee.C_Finalize!(nil)
            functions = nil
        }
    }

    private func list() throws -> CK_FUNCTION_LIST {
        guard let f = functions else {
            throw PKCS11Error(call: "C_Initialize", rv: CK_RV(CKR_CRYPTOKI_NOT_INITIALIZED))
        }
        return f.pointee
    }

    private func check(_ call: String, _ rv: CK_RV) throws {
        if rv != CK_RV(CKR_OK) { throw PKCS11Error(call: call, rv: rv) }
    }

    private func openSession(_ f: CK_FUNCTION_LIST, _ slot: CK_SLOT_ID) throws -> CK_SESSION_HANDLE {
        var s: CK_SESSION_HANDLE = 0
        try check("C_OpenSession", f.C_OpenSession!(slot, CK_FLAGS(CKF_SERIAL_SESSION), nil, nil, &s))
        return s
    }

    private func find(_ f: CK_FUNCTION_LIST, _ s: CK_SESSION_HANDLE, _ t: Template) throws -> [CK_OBJECT_HANDLE] {
        try withExtendedLifetime(t) {
            var attrs = t.attributes
            try check("C_FindObjectsInit", f.C_FindObjectsInit!(s, &attrs, CK_ULONG(attrs.count)))
        }
        defer { _ = f.C_FindObjectsFinal!(s) }
        var found: [CK_OBJECT_HANDLE] = []
        var batch = [CK_OBJECT_HANDLE](repeating: 0, count: 16)
        var n: CK_ULONG = 0
        repeat {
            try check("C_FindObjects", f.C_FindObjects!(s, &batch, CK_ULONG(batch.count), &n))
            found += batch.prefix(Int(n))
        } while n > 0
        return found
    }

    /// One attribute's value, or nil if the object doesn't have it.
    private func attribute(_ f: CK_FUNCTION_LIST, _ s: CK_SESSION_HANDLE, _ o: CK_OBJECT_HANDLE,
                           _ type: CK_ATTRIBUTE_TYPE) -> [UInt8]? {
        var a = CK_ATTRIBUTE(type: type, pValue: nil, ulValueLen: 0)
        guard f.C_GetAttributeValue!(s, o, &a, 1) == CK_RV(CKR_OK), a.ulValueLen != CK_ULONG.max else {
            return nil
        }
        if a.ulValueLen == 0 { return [] }
        var value = [UInt8](repeating: 0, count: Int(a.ulValueLen))
        let rv = value.withUnsafeMutableBytes { buf -> CK_RV in
            a.pValue = buf.baseAddress
            return f.C_GetAttributeValue!(s, o, &a, 1)
        }
        return rv == CK_RV(CKR_OK) ? Array(value.prefix(Int(a.ulValueLen))) : nil
    }

    private func ulong(_ bytes: [UInt8]?) -> CK_ULONG? {
        guard let bytes, bytes.count == MemoryLayout<CK_ULONG>.size else { return nil }
        return bytes.withUnsafeBytes { $0.loadUnaligned(as: CK_ULONG.self) }
    }
}

/// A search template: CK_ATTRIBUTEs whose values it owns until it is released.
private final class Template {
    private(set) var attributes: [CK_ATTRIBUTE] = []

    deinit {
        for a in attributes { a.pValue?.deallocate() }
    }

    func add(_ type: CK_ATTRIBUTE_TYPE, _ bytes: [UInt8]) -> Template {
        let p = UnsafeMutableRawPointer.allocate(byteCount: max(bytes.count, 1),
                                                 alignment: MemoryLayout<CK_ULONG>.alignment)
        bytes.withUnsafeBytes { if let b = $0.baseAddress { p.copyMemory(from: b, byteCount: bytes.count) } }
        attributes.append(CK_ATTRIBUTE(type: type, pValue: p, ulValueLen: CK_ULONG(bytes.count)))
        return self
    }

    func add(_ type: CK_ATTRIBUTE_TYPE, ulong v: CK_ULONG) -> Template {
        add(type, withUnsafeBytes(of: v) { Array($0) })
    }

    func add(_ type: CK_ATTRIBUTE_TYPE, bool v: Bool) -> Template {
        add(type, [v ? 1 : 0])
    }
}
