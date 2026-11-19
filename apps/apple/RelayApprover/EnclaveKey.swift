// The three Secure Enclave keys behind relay-ffi's `DeviceKey` trait.
//
// - device key: `.privateKeyUsage` + `.biometryCurrentSet`. Signs responses, denials and the
//   key bindings, so every signature needs a fresh Face ID / Touch ID. The approval flow
//   evaluates one LAContext and hands it here, so one biometric covers the whole approval.
// - auth key: `.privateKeyUsage` only. Signs routine relay calls (polling), never responses.
// - admin key: `.privateKeyUsage` + `.biometryCurrentSet`. Signs the Clients and Approvers calls
//   (wire-format §8.5). One LAContext covers a screen session of at most an hour.
//
// Rust hands over the exact bytes to sign; CryptoKit hashes them with SHA-256 and returns the
// raw r || s signature (wire-format §1.4). Rust checks every signature before it is used.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum EnclaveKeyError: Error, LocalizedError {
    case keychain(OSStatus)
    case accessControl
    case noBiometricContext

    var errorDescription: String? {
        switch self {
        case .keychain(let s): return "Keychain error \(s)"
        case .accessControl: return "Could not create the key's access control"
        case .noBiometricContext: return "Face ID is needed first"
        }
    }
}

final class EnclaveKey: DeviceKey, @unchecked Sendable {
    enum Kind: String {
        case device = "device-key"
        case auth = "relay-auth-key"
        case admin = "admin-auth-key"

        var needsBiometric: Bool { self != .auth }
    }

    let kind: Kind
    private let lock = NSLock()
    private var context: LAContext?
    private let blob: Data
    private let publicKeyDER: Data

    /// Load the key from the keychain, or create it in the Secure Enclave.
    init(_ kind: Kind) throws {
        self.kind = kind
        if let blob = try Keychain.read(account: kind.rawValue) {
            self.blob = blob
        } else {
            self.blob = try Self.create(kind)
            try Keychain.write(account: kind.rawValue, data: blob)
        }
        publicKeyDER = try Self.publicKey(blob)
    }

    /// The evaluated biometric context for the next signatures (device and admin keys).
    func use(_ context: LAContext?) {
        lock.lock()
        self.context = context
        lock.unlock()
    }

    func publicKey() -> Data { publicKeyDER }

    func sign(message: Data) throws -> Data {
        lock.lock()
        let ctx = context
        lock.unlock()
        do {
            #if targetEnvironment(simulator)
            let key = try P256.Signing.PrivateKey(rawRepresentation: blob)
            return try key.signature(for: message).rawRepresentation
            #else
            if kind.needsBiometric && ctx == nil { throw EnclaveKeyError.noBiometricContext }
            let key = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: blob, authenticationContext: ctx)
            return try key.signature(for: message).rawRepresentation
            #endif
        } catch {
            throw PlatformError.Failed(message: error.localizedDescription)
        }
    }

    /// Delete every key (re-enrollment from scratch).
    static func reset() {
        Keychain.delete(account: Kind.device.rawValue)
        Keychain.delete(account: Kind.auth.rawValue)
        Keychain.delete(account: Kind.admin.rawValue)
    }

    private static func create(_ kind: Kind) throws -> Data {
        #if targetEnvironment(simulator)
        // The simulator has no Secure Enclave: a software key, for development only.
        return P256.Signing.PrivateKey().rawRepresentation
        #else
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if kind.needsBiometric { flags.insert(.biometryCurrentSet) }
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil)
        else { throw EnclaveKeyError.accessControl }
        return try SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: false, accessControl: ac
        ).dataRepresentation
        #endif
    }

    private static func publicKey(_ blob: Data) throws -> Data {
        #if targetEnvironment(simulator)
        return try P256.Signing.PrivateKey(rawRepresentation: blob).publicKey.derRepresentation
        #else
        // Reading the public key needs no authentication.
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        return try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: blob, authenticationContext: ctx
        ).publicKey.derRepresentation
        #endif
    }
}

/// Ask for Face ID / Touch ID once; the returned context authorizes the device key's
/// signatures for this approval.
func evaluateBiometrics(reason: String) async throws -> LAContext? {
    #if targetEnvironment(simulator)
    return nil
    #else
    let ctx = LAContext()
    try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
    return ctx
    #endif
}

/// The key blobs (Secure Enclave-encrypted on devices) in the data-protection keychain,
/// this device only.
enum Keychain {
    private static let service = "relay-approver"

    static func read(account: String) throws -> Data? {
        var out: AnyObject?
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
        ]
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecItemNotFound { return nil }
        guard s == errSecSuccess else { throw EnclaveKeyError.keychain(s) }
        return out as? Data
    }

    static func write(account: String, data: Data) throws {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data,
        ]
        let s = SecItemAdd(q as CFDictionary, nil)
        guard s == errSecSuccess else { throw EnclaveKeyError.keychain(s) }
    }

    static func delete(account: String) {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ]
        SecItemDelete(q as CFDictionary)
    }
}
