//! Shared harness for the module tests: a TLS relay and the three fixture approvers in a
//! background runtime, and helpers that drive the provider through its C ABI.
#![allow(dead_code)]

use std::ptr::null_mut;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

pub use cryptoki_sys::*;
pub use relay_pkcs11::ffi::*;
use relay_test_approver::approver::{Approver, Behavior, Config};

pub struct Env {
    pub rt: tokio::runtime::Runtime,
    pub dir: std::path::PathBuf,
    pub relay: Arc<relay_server::state::AppState>,
}

pub fn approved(e: &Env) -> u64 {
    e.relay.metrics.responses_approved.load(Ordering::SeqCst)
}

pub fn start() -> Env {
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
        manifest_file: Some(dir.join("manifest.json")),
        manifest_signer: Some(dir.join("signer.asc")),
        hardware_attestation: relay_core::hw_attestation::PolicyConfig {
            require: true,
            roots_file: Some(dir.join("attestation-root.pem")),
        },
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
    Env { rt, dir, relay }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn ck(rv: CK_RV, what: &str) {
    assert_eq!(rv, CKR_OK, "{what}: rv = 0x{rv:x}");
}

pub fn ulong_attr(t: CK_ATTRIBUTE_TYPE, v: &CK_ULONG) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: t,
        pValue: v as *const CK_ULONG as *mut _,
        ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }
}

pub fn bytes_attr(t: CK_ATTRIBUTE_TYPE, v: &[u8]) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: t,
        pValue: v.as_ptr() as *mut _,
        ulValueLen: v.len() as CK_ULONG,
    }
}

/// Find the object with this class and label in a session.
pub fn find(s: CK_SESSION_HANDLE, class: CK_OBJECT_CLASS, label: &str) -> Option<CK_OBJECT_HANDLE> {
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

pub fn attr(s: CK_SESSION_HANDLE, h: CK_OBJECT_HANDLE, t: CK_ATTRIBUTE_TYPE) -> Vec<u8> {
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

pub fn open(slot: CK_SLOT_ID) -> CK_SESSION_HANDLE {
    let mut s = 0;
    // SAFETY: out-pointer to a local.
    ck(
        unsafe { C_OpenSession(slot, CKF_SERIAL_SESSION, null_mut(), None, &mut s) },
        "OpenSession",
    );
    s
}

pub fn mech(m: CK_MECHANISM_TYPE) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: m,
        pParameter: null_mut(),
        ulParameterLen: 0,
    }
}

/// C_SignInit + C_Sign with the length-query pattern.
pub fn sign(
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

pub fn oaep_params() -> CK_RSA_PKCS_OAEP_PARAMS {
    CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        source: CKZ_DATA_SPECIFIED,
        pSourceData: null_mut(),
        ulSourceDataLen: 0,
    }
}

pub fn verify_ec(point_der: &[u8], msg_or_digest: &[u8], sig: &[u8], prehashed: bool) {
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

pub fn rsa_key(s: CK_SESSION_HANDLE, h: CK_OBJECT_HANDLE) -> rsa::PublicKey {
    let n = rsa::BoxedUint::from_be_slice_vartime(&attr(s, h, CKA_MODULUS));
    let e = rsa::BoxedUint::from_be_slice_vartime(&attr(s, h, CKA_PUBLIC_EXPONENT));
    rsa::PublicKey::new(n, e).unwrap()
}

/// Every file under `dir`, recursively.
pub fn files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(files(&p))
        } else {
            out.push(p)
        }
    }
    out
}
