//! Manifest JSON parsing and validation (run after the signature check in production).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = relay_core::Manifest::from_json_unverified(data) {
        let _ = m.tokens();
        let _ = relay_core::ManifestDraft::from_json(data).and_then(|d| d.to_json());
    }
});
