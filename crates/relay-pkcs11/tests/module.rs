//! The provider driven through its C function table, as a PKCS#11 caller would, against a
//! real relay (TLS) and the three fixture approvers. Failure handling rows covered here:
//! role violation, mechanism not allowed, signed denial, unattested device, buffer too small,
//! and the length-query second call.

mod common;

use std::ptr::null_mut;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::*;

#[test]
fn module_end_to_end() {
    let env = start();
    // SAFETY: the whole test drives the module through its C ABI with valid arguments.
    unsafe {
        let mut list: CK_FUNCTION_LIST_PTR = null_mut();
        ck(C_GetFunctionList(&mut list), "GetFunctionList");
        assert!(!list.is_null() && (*list).C_Encrypt.is_some());
        assert_eq!(
            C_GetSlotList(CK_TRUE, null_mut(), &mut 0),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
        ck(C_Initialize(null_mut()), "Initialize");
        assert_eq!(C_Initialize(null_mut()), CKR_CRYPTOKI_ALREADY_INITIALIZED);

        // Discovery: three tokens from the manifest; keys appear once pairing is approved.
        let mut n: CK_ULONG = 0;
        ck(C_GetSlotList(CK_TRUE, null_mut(), &mut n), "GetSlotList");
        assert_eq!(n, 3, "one slot per manifest token");
        let mut info: CK_TOKEN_INFO = std::mem::zeroed();
        ck(C_GetTokenInfo(0, &mut info), "GetTokenInfo");
        assert!(std::str::from_utf8(&info.label)
            .unwrap()
            .starts_with("softcard-a"));
        assert_eq!(info.flags & CKF_LOGIN_REQUIRED, 0, "no PIN on the client");
        let sa = open(0);
        let start = Instant::now();
        let sign_ec = loop {
            if let Some(h) = find(sa, CKO_PRIVATE_KEY, "sign-ec") {
                break h;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "pairing never approved"
            );
            std::thread::sleep(Duration::from_millis(300));
        };
        assert!(
            find(sa, CKO_PRIVATE_KEY, "attest").is_none(),
            "attest keys are never exposed"
        );
        assert!(
            find(sa, CKO_PRIVATE_KEY, "unapproved").is_none(),
            "not approved for this client"
        );
        assert_eq!(attr(sa, sign_ec, CKA_SIGN), vec![CK_TRUE]);
        assert_eq!(attr(sa, sign_ec, CKA_DECRYPT), vec![CK_FALSE]);
        assert_eq!(attr(sa, sign_ec, CKA_ID), vec![2]);
        let mut a = CK_ATTRIBUTE {
            type_: CKA_VALUE,
            pValue: null_mut(),
            ulValueLen: 0,
        };
        assert_eq!(
            C_GetAttributeValue(sa, sign_ec, &mut a, 1),
            CKR_ATTRIBUTE_SENSITIVE
        );

        // sign key, hash-and-sign: one approval serves both calls of the length query.
        let before = approved(&env);
        let msg = b"a release tag";
        let sig = sign(sa, sign_ec, CKM_ECDSA_SHA256, msg).unwrap();
        assert_eq!(
            approved(&env) - before,
            1,
            "length query + real call = one approval"
        );
        let pub_ec = find(sa, CKO_PUBLIC_KEY, "sign-ec").unwrap();
        verify_ec(&attr(sa, pub_ec, CKA_EC_POINT), msg, &sig, false);

        // Buffer too small keeps the result cached: still one approval.
        let before = approved(&env);
        let mut m = mech(CKM_ECDSA_SHA256);
        ck(C_SignInit(sa, &mut m, sign_ec), "SignInit");
        let mut small = [0u8; 10];
        let mut len: CK_ULONG = small.len() as CK_ULONG;
        assert_eq!(
            C_Sign(
                sa,
                msg.as_ptr() as *mut _,
                msg.len() as CK_ULONG,
                small.as_mut_ptr(),
                &mut len
            ),
            CKR_BUFFER_TOO_SMALL
        );
        assert_eq!(len, 64);
        let mut big = [0u8; 64];
        ck(
            C_Sign(
                sa,
                msg.as_ptr() as *mut _,
                msg.len() as CK_ULONG,
                big.as_mut_ptr(),
                &mut len,
            ),
            "Sign after BUFFER_TOO_SMALL",
        );
        assert_eq!(approved(&env) - before, 1);

        // Multi-part hash-and-sign with an RSA sign key.
        let sign_rsa = find(sa, CKO_PRIVATE_KEY, "sign-rsa").unwrap();
        let mut m = mech(CKM_SHA256_RSA_PKCS);
        ck(C_SignInit(sa, &mut m, sign_rsa), "SignInit rsa");
        ck(
            C_SignUpdate(sa, b"a release ".as_ptr() as *mut _, 10),
            "SignUpdate",
        );
        ck(C_SignUpdate(sa, b"tag".as_ptr() as *mut _, 3), "SignUpdate");
        let mut out = vec![0u8; 256];
        let mut len: CK_ULONG = 256;
        ck(C_SignFinal(sa, out.as_mut_ptr(), &mut len), "SignFinal");
        let pk = rsa_key(sa, find(sa, CKO_PUBLIC_KEY, "sign-rsa").unwrap());
        use sha2::Digest;
        pk.verify(
            rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
            &sha2::Sha256::digest(msg),
            &out,
        )
        .unwrap();

        // auth keys: raw digest (ECDSA) and DigestInfo (RSA-PKCS).
        let auth_ec = find(sa, CKO_PRIVATE_KEY, "auth-ec").unwrap();
        let digest = sha2::Sha256::digest(b"ssh challenge");
        let sig = sign(sa, auth_ec, CKM_ECDSA, &digest).unwrap();
        verify_ec(
            &attr(
                sa,
                find(sa, CKO_PUBLIC_KEY, "auth-ec").unwrap(),
                CKA_EC_POINT,
            ),
            &digest,
            &sig,
            true,
        );
        let auth_rsa = find(sa, CKO_PRIVATE_KEY, "auth-rsa").unwrap();
        let mut di = relay_core::padding::SHA256_DIGEST_INFO_PREFIX.to_vec();
        di.extend_from_slice(&digest);
        let sig = sign(sa, auth_rsa, CKM_RSA_PKCS, &di).unwrap();
        rsa_key(sa, find(sa, CKO_PUBLIC_KEY, "auth-rsa").unwrap())
            .verify(rsa::Pkcs1v15Sign::new_unprefixed(), &di, &sig)
            .unwrap();

        // encrypt key: C_Encrypt in software, C_Decrypt through the relay.
        let enc_pub = find(sa, CKO_PUBLIC_KEY, "openbao-unseal").unwrap();
        let enc_priv = find(sa, CKO_PRIVATE_KEY, "openbao-unseal").unwrap();
        let mut p = oaep_params();
        let mut m = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: &mut p as *mut _ as *mut _,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };
        let pt = b"the unseal key";
        let before = approved(&env);
        ck(C_EncryptInit(sa, &mut m, enc_pub), "EncryptInit");
        let mut len: CK_ULONG = 0;
        ck(
            C_Encrypt(
                sa,
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
                sa,
                pt.as_ptr() as *mut _,
                pt.len() as CK_ULONG,
                ct.as_mut_ptr(),
                &mut len,
            ),
            "Encrypt",
        );
        assert_eq!(approved(&env), before, "encryption needs no approval");
        ck(C_DecryptInit(sa, &mut m, enc_priv), "DecryptInit");
        let mut len: CK_ULONG = 0;
        ck(
            C_Decrypt(
                sa,
                ct.as_mut_ptr(),
                ct.len() as CK_ULONG,
                null_mut(),
                &mut len,
            ),
            "Decrypt (length)",
        );
        let mut out = vec![0u8; len as usize];
        ck(
            C_Decrypt(
                sa,
                ct.as_mut_ptr(),
                ct.len() as CK_ULONG,
                out.as_mut_ptr(),
                &mut len,
            ),
            "Decrypt",
        );
        assert_eq!(&out[..len as usize], pt);
        assert_eq!(approved(&env) - before, 1);
        never_on_disk(&env, pt, &ct);

        // Failure handling: rejected locally, nothing sent.
        let before = env.relay.metrics.requests_accepted.load(Ordering::SeqCst);
        assert_eq!(
            C_DecryptInit(sa, &mut m, sign_ec),
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            "role violation"
        );
        assert_eq!(
            C_EncryptInit(sa, &mut m, find(sa, CKO_PUBLIC_KEY, "sign-ec").unwrap()),
            CKR_KEY_FUNCTION_NOT_PERMITTED
        );
        let mut raw = mech(CKM_ECDSA);
        assert_eq!(
            C_SignInit(sa, &mut raw, sign_ec),
            CKR_MECHANISM_INVALID,
            "mechanism not allowed"
        );
        let mut bad = oaep_params();
        bad.hashAlg = CKM_SHA_1;
        let mut m1 = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: &mut bad as *mut _ as *mut _,
            ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
        };
        assert_eq!(
            C_DecryptInit(sa, &mut m1, enc_priv),
            CKR_MECHANISM_PARAM_INVALID
        );
        assert_eq!(
            env.relay.metrics.requests_accepted.load(Ordering::SeqCst),
            before,
            "no request was sent"
        );

        // Signed denial (device B) and an unattested device (device C).
        let sb = open(1);
        let denied = find(sb, CKO_PRIVATE_KEY, "denied").unwrap();
        assert_eq!(
            sign(sb, denied, CKM_ECDSA, &digest),
            Err(CKR_FUNCTION_REJECTED)
        );
        let sc = open(2);
        let stale = find(sc, CKO_PRIVATE_KEY, "stale").unwrap();
        assert_eq!(sign(sc, stale, CKM_ECDSA, &digest), Err(CKR_DEVICE_ERROR));

        ck(C_CloseAllSessions(0), "CloseAllSessions");
        assert_eq!(C_CloseSession(sa), CKR_SESSION_HANDLE_INVALID);
        ck(C_Finalize(null_mut()), "Finalize");
        assert_eq!(C_Finalize(null_mut()), CKR_CRYPTOKI_NOT_INITIALIZED);
    }
}

/// Decrypt content never reaches storage: no file written by the relay (SQLite and its WAL),
/// the approvers or the provider holds the plaintext or any 32-byte window of the ciphertext,
/// and the audit log keeps only hashes for the decrypt.
fn never_on_disk(env: &Env, pt: &[u8], ct: &[u8]) {
    // Let SQLite flush and the WAL settle.
    std::thread::sleep(Duration::from_millis(500));
    let windows: Vec<&[u8]> = ct.chunks(32).filter(|c| c.len() == 32).collect();
    let all = files(&env.dir);
    assert!(
        all.iter().any(|p| p.to_string_lossy().contains("relay.db")),
        "relay database present"
    );
    for path in all {
        let data = std::fs::read(&path).unwrap_or_default();
        let has = |needle: &[u8]| data.windows(needle.len()).any(|w| w == needle);
        assert!(!has(pt), "plaintext found in {}", path.display());
        for w in &windows {
            assert!(!has(w), "ciphertext found in {}", path.display());
        }
    }
    let rows = env
        .rt
        .block_on(relay_server::db::audit_since(&env.relay.db, 0))
        .unwrap();
    let dec: Vec<_> = rows
        .iter()
        .filter(|r| r.op.as_deref() == Some("decrypt"))
        .collect();
    assert!(dec.len() >= 2, "decrypt request and response are audited");
    for r in dec {
        assert!(
            r.request.is_none() && r.response.is_none(),
            "{} row stores decrypt bytes",
            r.event
        );
        assert!(
            r.input_sha256.is_some() && r.detail.as_deref().is_some_and(|d| d.contains("_sha256="))
        );
    }
    // Sign requests are still audited in full (spec: audit log).
    assert!(rows
        .iter()
        .any(|r| r.op.as_deref() == Some("sign") && r.request.is_some()));
}
