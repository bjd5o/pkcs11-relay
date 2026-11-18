//! Device attestation statements (wire-format §5).

use crate::cbor::{self, Fields, MapBuilder};
use crate::error::{Error, Result};
use crate::keys::{Algorithm, Fingerprint, PublicKey, Role};
use crate::manifest::Manifest;

pub const CONTEXT: &str = "relay-pkcs11/attestation/v1";

/// The fields of a statement without its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedAttestation {
    pub device_id: String,
    pub device_key: PublicKey,
    pub not_before: u64,
    pub not_after: u64,
    pub attest_key_fingerprint: Fingerprint,
}

impl UnsignedAttestation {
    pub fn new(
        device_id: &str,
        device_key: PublicKey,
        not_before: u64,
        not_after: u64,
        attest_key_fingerprint: Fingerprint,
    ) -> Result<Self> {
        check_id(device_id)?;
        if device_key.algorithm() != Algorithm::P256 {
            return Err(Error::InvalidKey("device keys must be P-256".into()));
        }
        if not_before >= not_after {
            return Err(Error::Decode("not_before must be before not_after".into()));
        }
        Ok(UnsignedAttestation {
            device_id: device_id.into(),
            device_key,
            not_before,
            not_after,
            attest_key_fingerprint,
        })
    }

    fn map(&self) -> MapBuilder {
        MapBuilder::new()
            .uint("v", 1)
            .text("device_id", &self.device_id)
            .bytes("device_key", self.device_key.spki())
            .text(
                "device_key_fingerprint",
                self.device_key.fingerprint().as_str(),
            )
            .uint("not_before", self.not_before)
            .uint("not_after", self.not_after)
            .text(
                "attest_key_fingerprint",
                self.attest_key_fingerprint.as_str(),
            )
    }

    /// The bytes the attest key signs (ECDSA P-256 over SHA-256 of these).
    pub fn to_be_signed(&self) -> Vec<u8> {
        cbor::signed_bytes(CONTEXT, &self.map().encode())
    }

    /// Attach a 64-byte `r || s` signature and encode the statement.
    pub fn with_signature(self, sig: [u8; 64]) -> AttestationStatement {
        let bytes = self.map().bytes("sig", &sig).encode();
        AttestationStatement {
            fields: self,
            sig,
            bytes,
        }
    }
}

/// A decoded (not yet verified) statement, with its exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationStatement {
    pub fields: UnsignedAttestation,
    pub sig: [u8; 64],
    bytes: Vec<u8>,
}

impl AttestationStatement {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Strict decode, including the `device_key_fingerprint` consistency check.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut f = Fields::new(cbor::decode_map(bytes)?);
        f.version()?;
        let sig = f.fixed::<64>("sig")?;
        let device_id = f.text("device_id")?;
        let not_after = f.uint("not_after")?;
        let device_key = PublicKey::from_spki(&f.bytes("device_key")?)?;
        let not_before = f.uint("not_before")?;
        let attest_key_fingerprint = Fingerprint::parse(&f.text("attest_key_fingerprint")?)?;
        let device_key_fingerprint = Fingerprint::parse(&f.text("device_key_fingerprint")?)?;
        f.finish()?;
        if &device_key_fingerprint != device_key.fingerprint() {
            return Err(Error::Decode(
                "device_key_fingerprint does not match device_key".into(),
            ));
        }
        let fields = UnsignedAttestation::new(
            &device_id,
            device_key,
            not_before,
            not_after,
            attest_key_fingerprint,
        )?;
        Ok(AttestationStatement {
            fields,
            sig,
            bytes: bytes.to_vec(),
        })
    }
}

/// What a verified attestation tells the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub device_id: String,
    pub device_key: PublicKey,
    pub not_before: u64,
    pub not_after: u64,
    pub attest_key_fingerprint: Fingerprint,
}

/// Steps 1–3 of wire-format §5.1: decode, find the manifest attest key, verify the signature.
/// Separate from the window check so `verify_response` can keep the spec's order.
pub(crate) fn verify_signature(bytes: &[u8], manifest: &Manifest) -> Result<AttestationStatement> {
    let st = AttestationStatement::decode(bytes)
        .map_err(|e| Error::AttestationInvalid(e.to_string()))?;
    let key = manifest
        .key(&st.fields.attest_key_fingerprint)
        .filter(|k| k.role == Role::Attest)
        .ok_or(Error::AttestationUnknownSigner)?;
    key.public_key
        .verify_message(&st.fields.to_be_signed(), &st.sig)
        .map_err(|_| Error::AttestationInvalid("signature does not verify".into()))?;
    Ok(st)
}

/// Step 4: `not_before - skew <= now <= not_after + skew`.
pub(crate) fn check_window(st: &AttestationStatement, now: u64, skew: u64) -> Result<()> {
    if now.saturating_add(skew) < st.fields.not_before
        || now > st.fields.not_after.saturating_add(skew)
    {
        return Err(Error::AttestationExpired);
    }
    Ok(())
}

/// Step 5: the window is no longer than the manifest allows.
pub(crate) fn check_window_length(st: &AttestationStatement, manifest: &Manifest) -> Result<()> {
    let window = st.fields.not_after - st.fields.not_before;
    if window > manifest.max_attestation_window_secs {
        return Err(Error::AttestationWindowTooLong {
            window,
            max: manifest.max_attestation_window_secs,
        });
    }
    Ok(())
}

/// `verify_attestation(statement, manifest, now, skew)` (wire-format §5.1).
pub fn verify_attestation(
    bytes: &[u8],
    manifest: &Manifest,
    now: u64,
    skew: u64,
) -> Result<VerifiedAttestation> {
    let st = verify_signature(bytes, manifest)?;
    check_window(&st, now, skew)?;
    check_window_length(&st, manifest)?;
    let f = st.fields;
    Ok(VerifiedAttestation {
        device_id: f.device_id,
        device_key: f.device_key,
        not_before: f.not_before,
        not_after: f.not_after,
        attest_key_fingerprint: f.attest_key_fingerprint,
    })
}

/// Steps 1–3 and 5 of §5.1: who signed the attestation and its window length, not whether it
/// is current. For the relay, which keeps routing to a device whose attestation expired so that
/// the device can renew it during its next approval; clients always run [`verify_attestation`].
pub fn verify_attestation_signer(bytes: &[u8], manifest: &Manifest) -> Result<VerifiedAttestation> {
    let st = verify_signature(bytes, manifest)?;
    check_window_length(&st, manifest)?;
    let f = st.fields;
    Ok(VerifiedAttestation {
        device_id: f.device_id,
        device_key: f.device_key,
        not_before: f.not_before,
        not_after: f.not_after,
        attest_key_fingerprint: f.attest_key_fingerprint,
    })
}

/// Client and device ids: 1–64 characters of `[a-z0-9-]`, not starting or ending with `-`.
pub fn check_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        && !id.starts_with('-')
        && !id.ends_with('-');
    if ok {
        Ok(())
    } else {
        Err(Error::Decode(format!("invalid id `{id}`")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The byte-exact example from wire-format §5.2.
    const WIRE_EXAMPLE: &str = "a861760163736967584013e38ddd96420e845f36e445709f416c9227410d28b5c08fe48fc4b60196fd61c82c595e14d8c90453a94fb0557f32bf171420a70834b7d5ca0bd3e03b997624696465766963655f69646c627269616e2d6970686f6e65696e6f745f61667465721a6b2083006a6465766963655f6b6579585b3059301306072a8648ce3d020106082a8648ce3d030107034200048b9432b61c9144081b2eff864829ab0440cbe555b62ada198b8131e4e8fcf1f4226fbd788f8a53a858048fc0751d0e773303972e8a645718d4a30553834565286a6e6f745f6265666f72651a6af8f600766174746573745f6b65795f66696e6765727072696e7478477368613235363a65613465383731613437393262633839313635336532653437653938336665653861306161636134323135333935316562383933373930303235373464313539766465766963655f6b65795f66696e6765727072696e7478477368613235363a64326433653066633462303537656532333139383534363534656335373437656236336133333935333433633364393031306166616464623030393766373836";

    #[test]
    fn decodes_and_reencodes_wire_example() {
        let bytes = hex::decode(WIRE_EXAMPLE).unwrap();
        let st = AttestationStatement::decode(&bytes).unwrap();
        assert_eq!(st.fields.device_id, "brian-iphone");
        assert_eq!(st.fields.not_before, 1_794_700_800);
        let again = st.fields.clone().with_signature(st.sig);
        assert_eq!(again.bytes(), &bytes[..]);
        // The signed bytes match the annotated hex in wire-format §5.2.
        assert!(hex::encode(st.fields.to_be_signed())
            .starts_with("72656c61792d706b637331312f6174746573746174696f6e2f763100a7617601"));
    }

    #[test]
    fn ids() {
        assert!(check_id("openbao-pi5").is_ok());
        for bad in ["", "-a", "a-", "A", "a_b", &"a".repeat(65)] {
            assert!(check_id(bad).is_err(), "{bad}");
        }
    }
}
