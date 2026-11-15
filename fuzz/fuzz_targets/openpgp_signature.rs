//! OpenPGP detached-signature and signer-key parsing.
#![no_main]
use libfuzzer_sys::fuzz_target;

const SIGNER: &[u8] = include_bytes!("../../crates/relay-core/tests/vectors/pgp/signer-ed25519.asc");
const MANIFEST: &[u8] = include_bytes!("../../crates/relay-core/tests/vectors/fixture/manifest.json");

fuzz_target!(|data: &[u8]| {
    let signer = relay_core::ManifestSigner::from_bytes(SIGNER).unwrap();
    let _ = relay_core::verify_manifest(MANIFEST, data, &signer, None, 1_794_744_000, 60);
    let _ = relay_core::ManifestSigner::from_bytes(data);
});
