//! ECC encryption (ECDH via C_DeriveKey, both KDFs, extractable and non-extractable derived
//! keys with AES-GCM) and P-384 / Ed25519 signing, through the C ABI against the relay and the
//! fixture approvers. Each result is checked against an independent software computation.

mod common;

use std::ptr::null_mut;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::*;

fn bool_attr(t: CK_ATTRIBUTE_TYPE, v: &CK_BBOOL) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: t,
        pValue: v as *const CK_BBOOL as *mut _,
        ulValueLen: 1,
    }
}

/// C_DeriveKey with CKM_ECDH1_DERIVE.
fn derive(
    s: CK_SESSION_HANDLE,
    base: CK_OBJECT_HANDLE,
    kdf: CK_ULONG,
    shared: &[u8],
    peer: &[u8],
    tpl: &[CK_ATTRIBUTE],
) -> Result<CK_OBJECT_HANDLE, CK_RV> {
    let mut params = CK_ECDH1_DERIVE_PARAMS {
        kdf,
        ulSharedDataLen: shared.len() as CK_ULONG,
        pSharedData: if shared.is_empty() {
            null_mut()
        } else {
            shared.as_ptr() as *mut _
        },
        ulPublicDataLen: peer.len() as CK_ULONG,
        pPublicData: peer.as_ptr() as *mut _,
    };
    let mut m = CK_MECHANISM {
        mechanism: CKM_ECDH1_DERIVE,
        pParameter: &mut params as *mut _ as *mut _,
        ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
    };
    let mut h = 0;
    // SAFETY: valid mechanism, template and out-pointer.
    let rv = unsafe {
        C_DeriveKey(
            s,
            &mut m,
            base,
            tpl.as_ptr() as *mut _,
            tpl.len() as CK_ULONG,
            &mut h,
        )
    };
    if rv == CKR_OK {
        Ok(h)
    } else {
        Err(rv)
    }
}

/// Fresh random bytes (the core's OS RNG).
fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    relay_core::signing::random_bytes(&mut b);
    b
}

/// The point inside CKA_EC_POINT's DER OCTET STRING.
fn point(der: &[u8]) -> Vec<u8> {
    assert_eq!(der[0], 0x04);
    assert_eq!(der[1] as usize, der.len() - 2);
    der[2..].to_vec()
}

fn gcm(iv: &[u8], aad: &[u8]) -> CK_GCM_PARAMS {
    CK_GCM_PARAMS {
        pIv: iv.as_ptr() as *mut _,
        ulIvLen: iv.len() as CK_ULONG,
        ulIvBits: 96,
        pAAD: aad.as_ptr() as *mut _,
        ulAADLen: aad.len() as CK_ULONG,
        ulTagBits: 128,
    }
}

#[test]
fn ecc_end_to_end() {
    let env = start();
    let mut secrets: Vec<Vec<u8>> = Vec::new();
    // SAFETY: the whole test drives the module through its C ABI with valid arguments.
    unsafe {
        ck(C_Initialize(null_mut()), "Initialize");
        let s = open(0);
        let start = Instant::now();
        while find(s, CKO_PRIVATE_KEY, "enc-p256").is_none() {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "pairing never approved"
            );
            std::thread::sleep(Duration::from_millis(300));
        }
        let secret_class: CK_ULONG = CKO_SECRET_KEY;
        let generic: CK_ULONG = CKK_GENERIC_SECRET;
        let aes: CK_ULONG = CKK_AES;
        let (t, f): (CK_BBOOL, CK_BBOOL) = (CK_TRUE, CK_FALSE);
        let extractable_tpl = [
            ulong_attr(CKA_CLASS, &secret_class),
            ulong_attr(CKA_KEY_TYPE, &generic),
            bool_attr(CKA_EXTRACTABLE, &t),
            bool_attr(CKA_SENSITIVE, &f),
            bool_attr(CKA_TOKEN, &f),
        ];

        // --- Key objects: EC encrypt keys derive, they do not decrypt ---
        for (label, kt) in [
            ("enc-p256", CKK_EC),
            ("enc-p384", CKK_EC),
            ("enc-x25519", CKK_EC_MONTGOMERY),
        ] {
            let h = find(s, CKO_PRIVATE_KEY, label).unwrap();
            assert_eq!(attr(s, h, CKA_DERIVE), vec![CK_TRUE], "{label}");
            assert_eq!(attr(s, h, CKA_DECRYPT), vec![CK_FALSE], "{label}");
            assert_eq!(
                attr(s, h, CKA_KEY_TYPE),
                (kt as CK_ULONG).to_ne_bytes().to_vec(),
                "{label}"
            );
        }

        // --- ECDH, CKD_NULL, extractable generic secret, against software ECDH ---
        let before = approved(&env);
        let pub_p256 = point(&attr(
            s,
            find(s, CKO_PUBLIC_KEY, "enc-p256").unwrap(),
            CKA_EC_POINT,
        ));
        let eph = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate_from_rng(
            &mut rand_core::UnwrapErr(getrandom::SysRng),
        );
        let peer = eph.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        let expect = p256::ecdh::diffie_hellman(
            eph.as_nonzero_scalar(),
            p256::PublicKey::from_sec1_bytes(&pub_p256)
                .unwrap()
                .as_affine(),
        );
        let base = find(s, CKO_PRIVATE_KEY, "enc-p256").unwrap();
        let k = derive(s, base, CKD_NULL, &[], &peer, &extractable_tpl).unwrap();
        assert_eq!(
            attr(s, k, CKA_VALUE),
            expect.raw_secret_bytes().to_vec(),
            "P-256 shared secret"
        );
        assert_eq!(
            attr(s, k, CKA_VALUE_LEN),
            (32 as CK_ULONG).to_ne_bytes().to_vec()
        );
        secrets.push(expect.raw_secret_bytes().to_vec());
        // The peer key may also come DER-wrapped (OCTET STRING).
        let mut der = vec![0x04, peer.len() as u8];
        der.extend_from_slice(&peer);
        let k2 = derive(s, base, CKD_NULL, &[], &der, &extractable_tpl).unwrap();
        assert_eq!(attr(s, k2, CKA_VALUE), expect.raw_secret_bytes().to_vec());
        assert_eq!(approved(&env) - before, 2, "one approval per derivation");

        // --- X9.63 SHA-256 KDF with shared data ---
        let len32: CK_ULONG = 32;
        let mut kdf_tpl = extractable_tpl.to_vec();
        kdf_tpl.push(ulong_attr(CKA_VALUE_LEN, &len32));
        let k = derive(s, base, CKD_SHA256_KDF, b"context", &peer, &kdf_tpl).unwrap();
        let mut want = [0u8; 32];
        ansi_x963_kdf::derive_key_into::<sha2::Sha256>(
            expect.raw_secret_bytes(),
            b"context",
            &mut want,
        )
        .unwrap();
        assert_eq!(attr(s, k, CKA_VALUE), want.to_vec(), "X9.63 KDF");
        secrets.push(want.to_vec());

        // --- P-384 ---
        let pub_p384 = point(&attr(
            s,
            find(s, CKO_PUBLIC_KEY, "enc-p384").unwrap(),
            CKA_EC_POINT,
        ));
        let eph = <p384::ecdsa::SigningKey as p384::elliptic_curve::Generate>::generate_from_rng(
            &mut rand_core::UnwrapErr(getrandom::SysRng),
        );
        let peer384 = eph.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        let expect384 = p384::ecdh::diffie_hellman(
            eph.as_nonzero_scalar(),
            p384::PublicKey::from_sec1_bytes(&pub_p384)
                .unwrap()
                .as_affine(),
        );
        let base384 = find(s, CKO_PRIVATE_KEY, "enc-p384").unwrap();
        let k = derive(s, base384, CKD_NULL, &[], &peer384, &extractable_tpl).unwrap();
        assert_eq!(
            attr(s, k, CKA_VALUE),
            expect384.raw_secret_bytes().to_vec(),
            "P-384 shared secret"
        );
        secrets.push(expect384.raw_secret_bytes().to_vec());

        // --- X25519 ---
        let pub_x: [u8; 32] = point(&attr(
            s,
            find(s, CKO_PUBLIC_KEY, "enc-x25519").unwrap(),
            CKA_EC_POINT,
        ))
        .try_into()
        .unwrap();
        let eph = x25519_dalek::StaticSecret::from(random::<32>());
        let peer_x = x25519_dalek::PublicKey::from(&eph).as_bytes().to_vec();
        let expect_x = eph.diffie_hellman(&x25519_dalek::PublicKey::from(pub_x));
        let base_x = find(s, CKO_PRIVATE_KEY, "enc-x25519").unwrap();
        let k = derive(s, base_x, CKD_NULL, &[], &peer_x, &extractable_tpl).unwrap();
        assert_eq!(
            attr(s, k, CKA_VALUE),
            expect_x.as_bytes().to_vec(),
            "X25519 shared secret"
        );
        secrets.push(expect_x.as_bytes().to_vec());

        // --- Non-extractable AES key: usable only through the provider's AES-GCM ---
        let aes_tpl = [
            ulong_attr(CKA_CLASS, &secret_class),
            ulong_attr(CKA_KEY_TYPE, &aes),
            ulong_attr(CKA_VALUE_LEN, &len32),
        ];
        let ak = derive(s, base384, CKD_SHA256_KDF, b"aes", &peer384, &aes_tpl).unwrap();
        let mut a = CK_ATTRIBUTE {
            type_: CKA_VALUE,
            pValue: null_mut(),
            ulValueLen: 0,
        };
        assert_eq!(
            C_GetAttributeValue(s, ak, &mut a, 1),
            CKR_ATTRIBUTE_SENSITIVE,
            "AES key value stays inside"
        );
        assert_eq!(attr(s, ak, CKA_EXTRACTABLE), vec![CK_FALSE]);
        let mut key = [0u8; 32];
        ansi_x963_kdf::derive_key_into::<sha2::Sha256>(
            expect384.raw_secret_bytes(),
            b"aes",
            &mut key,
        )
        .unwrap();
        secrets.push(key.to_vec());
        let iv = random::<12>();
        let pt = b"a message sealed with the derived key";
        let sw_ct = relay_core::symmetric::aes_gcm_seal(&key, &iv, b"hdr", pt).unwrap();
        // Software ciphertext decrypts in the provider.
        let mut g = gcm(&iv, b"hdr");
        let mut m = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: &mut g as *mut _ as *mut _,
            ulParameterLen: std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
        };
        ck(C_DecryptInit(s, &mut m, ak), "DecryptInit AES-GCM");
        let mut len: CK_ULONG = 0;
        ck(
            C_Decrypt(
                s,
                sw_ct.as_ptr() as *mut _,
                sw_ct.len() as CK_ULONG,
                null_mut(),
                &mut len,
            ),
            "Decrypt (length)",
        );
        let mut out = vec![0u8; len as usize];
        ck(
            C_Decrypt(
                s,
                sw_ct.as_ptr() as *mut _,
                sw_ct.len() as CK_ULONG,
                out.as_mut_ptr(),
                &mut len,
            ),
            "Decrypt",
        );
        assert_eq!(&out[..len as usize], pt);
        // Provider ciphertext decrypts in software.
        ck(C_EncryptInit(s, &mut m, ak), "EncryptInit AES-GCM");
        let mut len: CK_ULONG = 0;
        ck(
            C_Encrypt(
                s,
                pt.as_ptr() as *mut _,
                pt.len() as CK_ULONG,
                null_mut(),
                &mut len,
            ),
            "Encrypt (length)",
        );
        let mut ct = vec![0u8; len as usize];
        ck(
            C_Encrypt(
                s,
                pt.as_ptr() as *mut _,
                pt.len() as CK_ULONG,
                ct.as_mut_ptr(),
                &mut len,
            ),
            "Encrypt",
        );
        assert_eq!(
            &*relay_core::symmetric::aes_gcm_open(&key, &iv, b"hdr", &ct).unwrap(),
            pt
        );
        // Tampering is caught.
        let mut bad = sw_ct.clone();
        bad[3] ^= 1;
        ck(C_DecryptInit(s, &mut m, ak), "DecryptInit");
        let mut len: CK_ULONG = 256;
        let mut out = vec![0u8; 256];
        assert_eq!(
            C_Decrypt(
                s,
                bad.as_mut_ptr(),
                bad.len() as CK_ULONG,
                out.as_mut_ptr(),
                &mut len
            ),
            CKR_ENCRYPTED_DATA_INVALID
        );
        // A generic secret is not an AES key.
        assert_eq!(C_EncryptInit(s, &mut m, k), CKR_KEY_TYPE_INCONSISTENT);

        // --- Refusals, none of which sends a request ---
        let sent = env.relay.metrics.requests_accepted.load(Ordering::SeqCst);
        let mut token_tpl = extractable_tpl.to_vec();
        token_tpl[4] = bool_attr(CKA_TOKEN, &t);
        assert_eq!(
            derive(s, base, CKD_NULL, &[], &peer, &token_tpl),
            Err(CKR_TEMPLATE_INCONSISTENT),
            "derived keys never go to the token"
        );
        assert_eq!(
            derive(
                s,
                find(s, CKO_PRIVATE_KEY, "sign-ec").unwrap(),
                CKD_NULL,
                &[],
                &peer,
                &extractable_tpl
            ),
            Err(CKR_KEY_FUNCTION_NOT_PERMITTED)
        );
        assert_eq!(
            derive(
                s,
                find(s, CKO_PRIVATE_KEY, "openbao-unseal").unwrap(),
                CKD_NULL,
                &[],
                &peer,
                &extractable_tpl
            ),
            Err(CKR_MECHANISM_INVALID)
        );
        let mut off = peer.clone();
        off[20] ^= 1;
        assert_eq!(
            derive(s, base, CKD_NULL, &[], &off, &extractable_tpl),
            Err(CKR_MECHANISM_PARAM_INVALID),
            "off-curve peer key"
        );
        assert_eq!(
            derive(s, base, CKD_NULL, b"x", &peer, &extractable_tpl),
            Err(CKR_MECHANISM_PARAM_INVALID),
            "CKD_NULL takes no shared data"
        );
        let aes_bad_len: CK_ULONG = 20;
        let tpl = [
            ulong_attr(CKA_KEY_TYPE, &aes),
            ulong_attr(CKA_VALUE_LEN, &aes_bad_len),
        ];
        assert_eq!(
            derive(s, base, CKD_NULL, &[], &peer, &tpl),
            Err(CKR_ATTRIBUTE_VALUE_INVALID)
        );
        assert_eq!(
            env.relay.metrics.requests_accepted.load(Ordering::SeqCst),
            sent,
            "no request was sent"
        );

        // --- Destroying objects ---
        ck(C_DestroyObject(s, k2), "DestroyObject (derived)");
        let mut a = CK_ATTRIBUTE {
            type_: CKA_VALUE,
            pValue: null_mut(),
            ulValueLen: 0,
        };
        assert_eq!(
            C_GetAttributeValue(s, k2, &mut a, 1),
            CKR_OBJECT_HANDLE_INVALID
        );
        assert_eq!(C_DestroyObject(s, base), CKR_ACTION_PROHIBITED);

        // --- P-384 signing ---
        let msg = b"a release tag";
        let sp = find(s, CKO_PRIVATE_KEY, "sign-p384").unwrap();
        let sig = sign(s, sp, CKM_ECDSA_SHA384, msg).unwrap();
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point(&attr(
            s,
            find(s, CKO_PUBLIC_KEY, "sign-p384").unwrap(),
            CKA_EC_POINT,
        )))
        .unwrap();
        {
            use p384::ecdsa::signature::Verifier;
            vk.verify(msg, &p384::ecdsa::Signature::from_slice(&sig).unwrap())
                .unwrap();
        }
        use sha2::Digest;
        let d = sha2::Sha384::digest(b"ssh challenge");
        let ap = find(s, CKO_PRIVATE_KEY, "auth-p384").unwrap();
        let sig = sign(s, ap, CKM_ECDSA, &d).unwrap();
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point(&attr(
            s,
            find(s, CKO_PUBLIC_KEY, "auth-p384").unwrap(),
            CKA_EC_POINT,
        )))
        .unwrap();
        {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            vk.verify_prehash(&d, &p384::ecdsa::Signature::from_slice(&sig).unwrap())
                .unwrap();
        }

        // --- Ed25519 signing (sign and auth) ---
        for label in ["sign-ed25519", "auth-ed25519"] {
            let h = find(s, CKO_PRIVATE_KEY, label).unwrap();
            assert_eq!(
                attr(s, h, CKA_KEY_TYPE),
                (CKK_EC_EDWARDS as CK_ULONG).to_ne_bytes().to_vec()
            );
            let sig = sign(s, h, CKM_EDDSA, msg).unwrap();
            let pk: [u8; 32] = point(&attr(
                s,
                find(s, CKO_PUBLIC_KEY, label).unwrap(),
                CKA_EC_POINT,
            ))
            .try_into()
            .unwrap();
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
            vk.verify_strict(
                msg,
                &ed25519_dalek::Signature::from_bytes(&sig.try_into().unwrap()),
            )
            .unwrap();
        }
        // Ed25519ph is not supported.
        let mut ep = CK_EDDSA_PARAMS {
            phFlag: CK_TRUE,
            ulContextDataLen: 0,
            pContextData: null_mut(),
        };
        let mut m = CK_MECHANISM {
            mechanism: CKM_EDDSA,
            pParameter: &mut ep as *mut _ as *mut _,
            ulParameterLen: std::mem::size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
        };
        assert_eq!(
            C_SignInit(s, &mut m, find(s, CKO_PRIVATE_KEY, "sign-ed25519").unwrap()),
            CKR_MECHANISM_PARAM_INVALID
        );

        ck(C_CloseSession(s), "CloseSession");
        ck(C_Finalize(null_mut()), "Finalize");
    }

    // --- No derived secret ever reaches a disk ---
    std::thread::sleep(Duration::from_millis(500));
    for path in files(&env.dir) {
        let data = std::fs::read(&path).unwrap_or_default();
        for secret in &secrets {
            assert!(
                !data.windows(secret.len()).any(|w| w == secret.as_slice()),
                "a derived secret was found in {}",
                path.display()
            );
        }
    }
}
