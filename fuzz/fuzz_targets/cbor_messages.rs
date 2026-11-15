//! Every CBOR message decoder: none may panic, and anything accepted re-encodes identically.
#![no_main]
use libfuzzer_sys::fuzz_target;
use relay_core::attestation::AttestationStatement;
use relay_core::request::SignedRequest;
use relay_core::response::SignedResponse;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = relay_core::cbor::decode_map(data) {
        assert_eq!(relay_core::cbor::encode(&relay_core::cbor::Value::Map(m)), data);
    }
    if let Ok(a) = AttestationStatement::decode(data) {
        assert_eq!(a.bytes(), data);
        assert_eq!(a.fields.clone().with_signature(a.sig).bytes(), data);
    }
    if let Ok(r) = SignedRequest::decode(data) {
        assert_eq!(r.fields.clone().with_signature(r.client_sig).bytes(), data);
    }
    if let Ok(r) = SignedResponse::decode(data) {
        assert_eq!(r.fields.clone().with_signature(r.device_sig).bytes(), data);
    }
});
