// What the app keeps on disk: the setup file and relay-ffi's SavedState, as JSON in
// Application Support with complete file protection. Nothing secret: no PIN, no results, no
// private keys (those stay in the Secure Enclave).

import Foundation

/// The file `relayctl app-config` writes.
struct SetupFile: Codable, Equatable {
    var relay_url: String
    var relay_ca_pem: String?
    var manifest_url: String
    var manifest_signer: String
    var device_id: String
    var attestation_window_secs: UInt64

    var config: ApproverConfig {
        ApproverConfig(
            relayUrl: relay_url, relayCaPem: relay_ca_pem, manifestUrl: manifest_url,
            manifestSigner: manifest_signer, deviceId: device_id,
            attestationWindowSecs: attestation_window_secs, skewSecs: 60)
    }
}

private struct StoredClient: Codable {
    var clientId: String
    var publicKey: Data
    var keys: [String]
}

private struct StoredKey: Codable {
    var fingerprint: String
    var slot: UInt8
}

private struct StoredState: Codable {
    var manifest: Data?
    var manifestSignature: Data?
    var attestation: Data?
    var authBinding: Data?
    var clients: [StoredClient]
    var keys: [StoredKey]

    init(_ s: SavedState) {
        manifest = s.manifest
        manifestSignature = s.manifestSignature
        attestation = s.attestation
        authBinding = s.authBinding
        clients = s.clients.map { StoredClient(clientId: $0.clientId, publicKey: $0.publicKey, keys: $0.keys) }
        keys = s.keys.map { StoredKey(fingerprint: $0.fingerprint, slot: $0.slot) }
    }

    var saved: SavedState {
        SavedState(
            manifest: manifest, manifestSignature: manifestSignature, attestation: attestation,
            authBinding: authBinding,
            clients: clients.map { SavedClient(clientId: $0.clientId, publicKey: $0.publicKey, keys: $0.keys) },
            keys: keys.map { SavedKey(fingerprint: $0.fingerprint, slot: $0.slot) })
    }
}

enum Storage {
    private static var dir: URL {
        let d = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("RelayApprover", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    private static func write(_ data: Data, _ name: String) throws {
        #if os(iOS)
        try data.write(to: dir.appendingPathComponent(name), options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: dir.appendingPathComponent(name), options: [.atomic])
        #endif
    }

    private static func read(_ name: String) -> Data? {
        try? Data(contentsOf: dir.appendingPathComponent(name))
    }

    static func loadSetup() -> SetupFile? {
        read("setup.json").flatMap { try? JSONDecoder().decode(SetupFile.self, from: $0) }
    }

    static func saveSetup(_ s: SetupFile) throws {
        try write(JSONEncoder().encode(s), "setup.json")
    }

    static func loadState() -> SavedState {
        read("state.json").flatMap { try? JSONDecoder().decode(StoredState.self, from: $0) }?.saved
            ?? SavedState(
                manifest: nil, manifestSignature: nil, attestation: nil, authBinding: nil,
                clients: [], keys: [])
    }

    static func saveState(_ s: SavedState) throws {
        try write(JSONEncoder().encode(StoredState(s)), "state.json")
    }

    /// Forget everything (the keys are deleted separately).
    static func reset() {
        try? FileManager.default.removeItem(at: dir)
    }
}
