//! The provider driven through its C function table, as a PKCS#11 caller would, against a
//! real relay (TLS) and the three fixture approvers. Failure handling rows covered here:
//! role violation, mechanism not allowed, signed denial, unattested device, buffer too small,
//! and the length-query second call.

use std::ptr::{null, null_mut};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cryptoki_sys::*;
use relay_pkcs11::ffi::*;
use relay_test_approver::approver::{Approver, Behavior, Config};

struct Env {
    _rt: tokio::runtime::Runtime,
    relay: Arc<relay_server::state::AppState>,
}

fn approved(e: &Env) -> u64 {
    e.relay.metrics.responses_approved.load(Ordering::SeqCst)
}

fn start() -> Env {
    let mut b = [0u8; 8];
    relay_core::signing::random_bytes(&mut b);
    let dir = std::env::temp_dir().join(format!("relay-module-{}", hex(&b)));
    std::fs::create_dir_all(&dir).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    relay_test_approver::fixtures::generate(
        &dir,
        dir.to_str().unwrap(),
        &url,
        &["127.0.0.0/8".into()],
        relay_test_approver::relay::now(),
    )
    .unwrap();
    let cfg = relay_server::config::Config {
        data_dir: dir.join("relay"),
        ..Default::default()
    };
    let relay = rt.block_on(async {
        let st = relay_server::build_state(cfg).await.unwrap();
        let (cert, key) = (dir.join("relay-cert.pem"), dir.join("relay-key.pem"));
        let s = st.clone();
        tokio::spawn(async move { relay_server::serve_tls(listener, s, &cert, &key).await });
        for (name, b) in [
            ("a", Behavior::default()),
            (
                "b",
                Behavior {
                    deny: true,
                    delay: Duration::from_secs(1),
                    ..Default::default()
                },
            ),
            (
                "c",
                Behavior {
                    expired_attestation: true,
                    ..Default::default()
                },
            ),
        ] {
            let c: Config = toml::from_str(
                &std::fs::read_to_string(dir.join(format!("approver-{name}.toml"))).unwrap(),
            )
            .unwrap();
            let card =
                relay_softcard::SoftCard::load_dir(c.softcard_dir.as_ref().unwrap(), b"123456")
                    .unwrap();
            let a = Approver::start(c, b, Box::new(card)).await.unwrap();
            tokio::spawn(a.run());
        }
        st
    });
    std::env::set_var("RELAY_PKCS11_CONFIG", dir.join("provider.toml"));
    Env { _rt: rt, relay }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ck(rv: CK_RV, what: &str) {
    assert_eq!(rv, CKR_OK, "{what}: rv = 0x{rv:x}");
}

fn ulong_attr(t: CK_ATTRIBUTE_TYPE, v: &CK_ULONG) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: t,
        pValue: v as *const CK_ULONG as *mut _,
        ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }
}

fn bytes_attr(t: CK_ATTRIBUTE_TYPE, v: &[u8]) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: t,
        pValue: v.as_ptr() as *mut _,
        ulValueLen: v.len() as CK_ULONG,
    }
}

/// Find the object with this class and label in a session.
fn find(s: CK_SESSION_HANDLE, class: CK_OBJECT_CLASS, label: &str) -> Option<CK_OBJECT_HANDLE> {
    let tpl = [
        ulong_attr(CKA_CLASS, &class),
        bytes_attr(CKA_LABEL, label.as_bytes()),
    ];
    let mut h: CK_OBJECT_HANDLE = 0;
    let mut n: CK_ULONG = 0;
    // SAFETY: valid template, out-pointers to locals.
    unsafe {
        ck(
            C_FindObjectsInit(s, tpl.as_ptr() as *mut _, 2),
            "FindObjectsInit",
        );
        ck(C_FindObjects(s, &mut h, 1, &mut n), "FindObjects");
        ck(C_FindObjectsFinal(s), "FindObjectsFinal");
    }
    (n == 1).then_some(h)
}

fn attr(s: CK_SESSION_HANDLE, h: CK_OBJECT_HANDLE, t: CK_ATTRIBUTE_TYPE) -> Vec<u8> {
    let mut a = CK_ATTRIBUTE {
        type_: t,
        pValue: null_mut(),
        ulValueLen: 0,
    };
    // SAFETY: two-call pattern with a buffer of the size the first call reported.
    unsafe {
        ck(
            C_GetAttributeValue(s, h, &mut a, 1),
            "GetAttributeValue (length)",
        );
        let mut buf = vec![0u8; a.ulValueLen as usize];
        a.pValue = buf.as_mut_ptr() as *mut _;
        ck(C_GetAttributeValue(s, h, &mut a, 1), "GetAttributeValue");
        buf
    }
}

fn open(slot: CK_SLOT_ID) -> CK_SESSION_HANDLE {
    let mut s = 0;
    // SAFETY: out-pointer to a local.
    ck(
        unsafe { C_OpenSession(slot, CKF_SERIAL_SESSION, null_mut(), None, &mut s) },
        "OpenSession",
    );
    s
}

fn mech(m: CK_MECHANISM_TYPE) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: m,
        pParameter: null_mut(),
        ulParameterLen: 0,
    }
}

/// C_SignInit + C_Sign with the length-query pattern.
fn sign(
    s: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
    m: CK_MECHANISM_TYPE,
    data: &[u8],
) -> Result<Vec<u8>, CK_RV> {
    let mut mm = mech(m);
    // SAFETY: valid mechanism and buffers.
    unsafe {
        let rv = C_SignInit(s, &mut mm, key);
        if rv != CKR_OK {
            return Err(rv);
        }
        let mut len: CK_ULONG = 0;
        let rv = C_Sign(
            s,
            data.as_ptr() as *mut _,
            data.len() as CK_ULONG,
            null_mut(),
            &mut len,
        );
        if rv != CKR_OK {
            return Err(rv);
        }
        let mut out = vec![0u8; len as usize];
        ck(
            C_Sign(
                s,
                data.as_ptr() as *mut _,
                data.len() as CK_ULONG,
                out.as_mut_ptr(),
                &mut len,
            ),
            "Sign (second call)",
        );
        out.truncate(len as usize);
        Ok(out)
    }
}

fn oaep_params() -> CK_RSA_PKCS_OAEP_PARAMS {
    CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        source: CKZ_DATA_SPECIFIED,
        pSourceData: null_mut(),
        ulSourceDataLen: 0,
    }
}

fn verify_ec(point_der: &[u8], msg_or_digest: &[u8], sig: &[u8], prehashed: bool) {
    use p256::ecdsa::signature::{hazmat::PrehashVerifier, Verifier};
    assert_eq!(point_der[0], 0x04, "CKA_EC_POINT is an OCTET STRING");
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point_der[2..]).unwrap();
    let sig = p256::ecdsa::Signature::from_slice(sig).unwrap();
    if prehashed {
        vk.verify_prehash(msg_or_digest, &sig).unwrap()
    } else {
        vk.verify(msg_or_digest, &sig).unwrap()
    }
}

fn rsa_key(s: CK_SESSION_HANDLE, h: CK_OBJECT_HANDLE) -> rsa::PublicKey {
    let n = rsa::BoxedUint::from_be_slice_vartime(&attr(s, h, CKA_MODULUS));
    let e = rsa::BoxedUint::from_be_slice_vartime(&attr(s, h, CKA_PUBLIC_EXPONENT));
    rsa::PublicKey::new(n, e).unwrap()
}

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
    let _ = null::<u8>();
}
