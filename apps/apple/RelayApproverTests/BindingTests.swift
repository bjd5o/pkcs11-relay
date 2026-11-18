// Smoke tests of the Rust bindings compiled for this platform (simulator or Mac).

import CryptoKit
import XCTest
@testable import RelayApprover

final class BindingTests: XCTestCase {
    func testSignerFingerprintRejectsJunk() {
        XCTAssertThrowsError(try manifestSignerFingerprint(armored: "not a key"))
    }

    func testApproverRejectsANonP256DeviceKey() {
        let config = ApproverConfig(
            relayUrl: "https://127.0.0.1:9", relayCaPem: nil, manifestUrl: "https://127.0.0.1:9/v1/manifest",
            manifestSigner: "x", deviceId: "t", attestationWindowSecs: 60, skewSecs: 60,
            attestationRootsPem: nil)
        let bad = FixedKey(spki: Data([0x30, 0x00]))
        XCTAssertThrowsError(
            try Approver(
                config: config, deviceKey: bad, authKey: bad,
                saved: SavedState(
                    manifest: nil, manifestSignature: nil, attestation: nil, authBinding: nil,
                    clients: [], keys: [])))
    }

    /// The CryptoKit signature format is what Rust expects: raw r || s over SHA-256.
    func testCryptoKitRawSignatureIs64Bytes() throws {
        let k = P256.Signing.PrivateKey()
        let sig = try k.signature(for: Data("hello".utf8)).rawRepresentation
        XCTAssertEqual(sig.count, 64)
        XCTAssertTrue(k.publicKey.isValidSignature(
            try P256.Signing.ECDSASignature(rawRepresentation: sig), for: Data("hello".utf8)))
    }
}

private final class FixedKey: DeviceKey, @unchecked Sendable {
    let spki: Data
    init(spki: Data) { self.spki = spki }
    func publicKey() -> Data { spki }
    func sign(message: Data) throws -> Data { Data(count: 64) }
}
