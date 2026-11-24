// Checks a signature from the provider with the public key read through PKCS#11
// (CKA_EC_POINT, or CKA_MODULUS and CKA_PUBLIC_EXPONENT), using CryptoKit and Security only.

import CryptoKit
import Foundation
import Security

enum Verifier {
    struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    static func verify(_ key: SigningKey, _ result: SignResult, message: Data) throws -> Bool {
        switch result.scheme {
        case .ecdsaP256SHA256:
            let pub = try P256.Signing.PublicKey(x963Representation: try point(key))
            let sig = try P256.Signing.ECDSASignature(rawRepresentation: result.signature)
            return pub.isValidSignature(sig, for: message)
        case .ecdsaP384SHA384:
            let pub = try P384.Signing.PublicKey(x963Representation: try point(key))
            let sig = try P384.Signing.ECDSASignature(rawRepresentation: result.signature)
            return pub.isValidSignature(sig, for: message)
        case .ed25519:
            let pub = try Curve25519.Signing.PublicKey(rawRepresentation: try point(key))
            return pub.isValidSignature(result.signature, for: message)
        case .rsaPKCS1SHA256:
            guard let n = key.modulus, let e = key.exponent else { throw Failure(description: "no RSA public key") }
            let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic]
            var error: Unmanaged<CFError>?
            guard let pub = SecKeyCreateWithData(Data(rsaPublicKey(n, e)) as CFData, attrs as CFDictionary, &error) else {
                throw Failure(description: "RSA public key: \(error?.takeRetainedValue().localizedDescription ?? "?")")
            }
            return SecKeyVerifySignature(pub, .rsaSignatureMessagePKCS1v15SHA256, message as CFData,
                                         result.signature as CFData, &error)
        }
    }

    /// The contents of the DER OCTET STRING in CKA_EC_POINT.
    private static func point(_ key: SigningKey) throws -> Data {
        guard let der = key.ecPoint, der.count >= 2, der[0] == 0x04 else {
            throw Failure(description: "CKA_EC_POINT is not an OCTET STRING")
        }
        var i = 1
        var len = Int(der[i]); i += 1
        if len & 0x80 != 0 {
            let n = len & 0x7F
            guard n <= 2, der.count >= i + n else { throw Failure(description: "bad CKA_EC_POINT length") }
            len = der[i..<i + n].reduce(0) { $0 << 8 | Int($1) }
            i += n
        }
        guard der.count == i + len else { throw Failure(description: "bad CKA_EC_POINT length") }
        return Data(der[i...])
    }

    /// PKCS#1 RSAPublicKey DER (what SecKeyCreateWithData takes for RSA).
    private static func rsaPublicKey(_ n: [UInt8], _ e: [UInt8]) -> [UInt8] {
        func length(_ l: Int) -> [UInt8] {
            if l < 0x80 { return [UInt8(l)] }
            var bytes: [UInt8] = []
            var v = l
            while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
            return [0x80 | UInt8(bytes.count)] + bytes
        }
        func integer(_ b: [UInt8]) -> [UInt8] {
            var v = Array(b.drop { $0 == 0 })
            if v.isEmpty || v[0] & 0x80 != 0 { v.insert(0, at: 0) }
            return [0x02] + length(v.count) + v
        }
        let body = integer(n) + integer(e)
        return [0x30] + length(body.count) + body
    }
}
