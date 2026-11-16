//! The C ABI: the only `unsafe` code in the workspace. Each exported function catches panics
//! (mapping them to `CKR_GENERAL_ERROR`), checks the module is initialised in this process,
//! converts pointers to Rust values, and calls `provider.rs`.
#![allow(non_snake_case, clippy::missing_safety_doc)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use cryptoki_sys::*;
use relay_core::mechanism::{check_encrypt, check_key_mechanism, OaepParams, MAX_SIGN_MESSAGE_LEN};
use relay_core::{Mechanism, Op};
use zeroize::Zeroizing;

use crate::ffi_stubs::*;
use crate::provider::{mechanism_info, mechanisms_for, rv, Attr, Operation, Provider, Rv};
use crate::{config::Config, log};

// ---------- global state ----------

struct Global {
    /// The process that called `C_Initialize`: after `fork()` the child must initialise again.
    pid: u32,
    /// `None` when the configuration is unusable: the module then lists zero slots.
    provider: Option<Arc<Provider>>,
}

static STATE: Mutex<Option<Global>> = Mutex::new(None);

fn state() -> std::sync::MutexGuard<'static, Option<Global>> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// The provider for this process, or `CKR_CRYPTOKI_NOT_INITIALIZED`.
fn provider() -> Result<Option<Arc<Provider>>, Rv> {
    match &*state() {
        Some(g) if g.pid == std::process::id() => Ok(g.provider.clone()),
        _ => Err(CKR_CRYPTOKI_NOT_INITIALIZED),
    }
}

fn need_provider() -> Result<Arc<Provider>, Rv> {
    provider()?.ok_or(CKR_SLOT_ID_INVALID)
}

/// Run `f`, turning panics into `CKR_GENERAL_ERROR`: nothing unwinds across the C boundary.
fn guard(f: impl FnOnce() -> Result<(), Rv>) -> CK_RV {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => CKR_OK,
        Ok(Err(rv)) => rv,
        Err(_) => {
            log::error("internal panic caught at the PKCS#11 boundary");
            CKR_GENERAL_ERROR
        }
    }
}

// ---------- pointer helpers ----------

/// Write `v` to an out-pointer.
///
/// SAFETY (for callers): `p` must be null or valid for a write of `T`, per the PKCS#11 call
/// contract for that argument.
unsafe fn put<T>(p: *mut T, v: T) -> Result<(), Rv> {
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: non-null, and the caller guarantees validity for a write of T.
    unsafe { p.write(v) };
    Ok(())
}

/// View a caller buffer as a byte slice.
///
/// SAFETY (for callers): `p` must be null (with `len == 0`) or valid for reads of `len` bytes.
unsafe fn bytes<'a>(p: *const u8, len: CK_ULONG) -> Result<&'a [u8], Rv> {
    if len == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: non-null and valid for `len` bytes per the caller's contract.
    Ok(unsafe { std::slice::from_raw_parts(p, len as usize) })
}

/// Copy a template into owned (type, value) pairs.
///
/// SAFETY (for callers): `p` must point to `n` valid `CK_ATTRIBUTE`s whose `pValue` buffers
/// hold `ulValueLen` bytes.
unsafe fn template(
    p: *const CK_ATTRIBUTE,
    n: CK_ULONG,
) -> Result<Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)>, Rv> {
    if n == 0 {
        return Ok(Vec::new());
    }
    if p.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: the caller passes an array of `n` attributes.
    let attrs = unsafe { std::slice::from_raw_parts(p, n as usize) };
    attrs
        .iter()
        // SAFETY: each pValue holds ulValueLen bytes per the caller's contract.
        .map(|a| {
            Ok((
                a.type_,
                unsafe { bytes(a.pValue as *const u8, a.ulValueLen) }?.to_vec(),
            ))
        })
        .collect()
}

/// The PKCS#11 two-call convention for arrays: count when `out` is null, else copy.
///
/// SAFETY (for callers): `out` null or valid for `*count` writes; `count` valid.
unsafe fn put_list<T: Copy>(items: &[T], out: *mut T, count: *mut CK_ULONG) -> Result<(), Rv> {
    if count.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: count is non-null and valid per the caller's contract.
    let have = unsafe { *count } as usize;
    // SAFETY: as above.
    unsafe { *count = items.len() as CK_ULONG };
    if out.is_null() {
        return Ok(());
    }
    if have < items.len() {
        return Err(CKR_BUFFER_TOO_SMALL);
    }
    // SAFETY: out is valid for `have >= items.len()` elements.
    unsafe { std::ptr::copy_nonoverlapping(items.as_ptr(), out, items.len()) };
    Ok(())
}

fn padded<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [b' '; N];
    let b = s.as_bytes();
    let mut n = b.len().min(N);
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    out[..n].copy_from_slice(&b[..n]);
    out
}

const VERSION: CK_VERSION = CK_VERSION { major: 0, minor: 1 };

// ---------- general ----------

pub unsafe extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    guard(|| {
        if !pInitArgs.is_null() {
            // SAFETY: a non-null pInitArgs points to CK_C_INITIALIZE_ARGS (PKCS#11 §5.4).
            let a = unsafe { &*(pInitArgs as *const CK_C_INITIALIZE_ARGS) };
            if !a.pReserved.is_null() {
                return Err(CKR_ARGUMENTS_BAD);
            }
            let fns = [
                a.CreateMutex.is_some(),
                a.DestroyMutex.is_some(),
                a.LockMutex.is_some(),
                a.UnlockMutex.is_some(),
            ];
            if fns.iter().any(|x| *x) && !fns.iter().all(|x| *x) {
                return Err(CKR_ARGUMENTS_BAD);
            }
            // We always use OS locking; an application that only offers its own mutexes
            // cannot be served.
            if fns[0] && a.flags & CKF_OS_LOCKING_OK == 0 {
                return Err(CKR_CANT_LOCK);
            }
        }
        let mut st = state();
        if let Some(g) = &*st {
            if g.pid == std::process::id() {
                return Err(CKR_CRYPTOKI_ALREADY_INITIALIZED);
            }
        }
        // No threads, sockets or files before this point; config and key files are read now.
        let provider = match Config::from_env() {
            Ok(cfg) => {
                log::init(cfg.log_level.as_deref(), cfg.log_path.as_deref());
                match Provider::new(cfg) {
                    Ok(p) => Some(Arc::new(p)),
                    Err(e) => {
                        log::error(&format!("unusable configuration, listing no slots: {e}"));
                        None
                    }
                }
            }
            Err(e) => {
                log::error(&format!("no configuration, listing no slots: {e}"));
                None
            }
        };
        *st = Some(Global {
            pid: std::process::id(),
            provider,
        });
        Ok(())
    })
}

pub unsafe extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    guard(|| {
        if !pReserved.is_null() {
            return Err(CKR_ARGUMENTS_BAD);
        }
        provider()?;
        *state() = None;
        Ok(())
    })
}

pub unsafe extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    guard(|| {
        provider()?;
        let info = CK_INFO {
            cryptokiVersion: CK_VERSION {
                major: 2,
                minor: 40,
            },
            manufacturerID: padded("pkcs11-relay"),
            flags: 0,
            libraryDescription: padded("Approval-gated PKCS#11 relay"),
            libraryVersion: VERSION,
        };
        // SAFETY: pInfo is null or valid for a CK_INFO write.
        unsafe { put(pInfo, info) }
    })
}

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

/// The module's one exported symbol.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    guard(|| {
        // SAFETY: ppFunctionList is null or valid for a pointer write; the table is a
        // 'static immutable that callers only read.
        unsafe {
            put(
                ppFunctionList,
                &FUNCTION_LIST as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR,
            )
        }
    })
}

// ---------- slots and tokens ----------

pub unsafe extern "C" fn C_GetSlotList(
    _tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        let n = match provider()? {
            Some(p) => p.slots().len(),
            None => 0,
        };
        let ids: Vec<CK_SLOT_ID> = (0..n as CK_SLOT_ID).collect();
        // SAFETY: per the C_GetSlotList contract.
        unsafe { put_list(&ids, pSlotList, pulCount) }
    })
}

fn token_name(p: &Provider, slot: CK_SLOT_ID) -> Result<String, Rv> {
    p.slots()
        .get(slot as usize)
        .map(|s| s.token.clone())
        .ok_or(CKR_SLOT_ID_INVALID)
}

pub unsafe extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        let token = token_name(&p, slotID)?;
        let info = CK_SLOT_INFO {
            slotDescription: padded(&format!("pkcs11-relay {token}")),
            manufacturerID: padded("pkcs11-relay"),
            flags: CKF_TOKEN_PRESENT,
            hardwareVersion: VERSION,
            firmwareVersion: VERSION,
        };
        // SAFETY: pInfo is null or valid for a CK_SLOT_INFO write.
        unsafe { put(pInfo, info) }
    })
}

pub unsafe extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        let token = token_name(&p, slotID)?;
        let serial = relay_core::Fingerprint::of_spki(token.as_bytes()).to_string();
        let info = CK_TOKEN_INFO {
            label: padded(&token),
            manufacturerID: padded("pkcs11-relay"),
            model: padded("relay"),
            serialNumber: padded(&serial[7..23]),
            // No CKF_LOGIN_REQUIRED: the PIN is entered on the approver, never here.
            flags: CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED,
            ulMaxSessionCount: CK_EFFECTIVELY_INFINITE,
            ulSessionCount: CK_UNAVAILABLE_INFORMATION,
            ulMaxRwSessionCount: CK_EFFECTIVELY_INFINITE,
            ulRwSessionCount: CK_UNAVAILABLE_INFORMATION,
            ulMaxPinLen: 0,
            ulMinPinLen: 0,
            ulTotalPublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulTotalPrivateMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePrivateMemory: CK_UNAVAILABLE_INFORMATION,
            hardwareVersion: VERSION,
            firmwareVersion: VERSION,
            utcTime: [b' '; 16],
        };
        // SAFETY: pInfo is null or valid for a CK_TOKEN_INFO write.
        unsafe { put(pInfo, info) }
    })
}

pub unsafe extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: CK_MECHANISM_TYPE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        let slots = p.slots();
        let s = slots.get(slotID as usize).ok_or(CKR_SLOT_ID_INVALID)?;
        let mut mechs: Vec<CK_MECHANISM_TYPE> = s.keys.iter().flat_map(mechanisms_for).collect();
        mechs.sort_unstable();
        mechs.dedup();
        // SAFETY: per the C_GetMechanismList contract.
        unsafe { put_list(&mechs, pMechanismList, pulCount) }
    })
}

pub unsafe extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    pInfo: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        let slots = p.slots();
        let s = slots.get(slotID as usize).ok_or(CKR_SLOT_ID_INVALID)?;
        let algs: Vec<_> = s
            .keys
            .iter()
            .filter(|k| mechanisms_for(k).contains(&type_))
            .map(|k| k.algorithm)
            .collect();
        if algs.is_empty() {
            return Err(CKR_MECHANISM_INVALID);
        }
        let info = mechanism_info(type_, &algs).ok_or(CKR_MECHANISM_INVALID)?;
        // SAFETY: pInfo is null or valid for a CK_MECHANISM_INFO write.
        unsafe { put(pInfo, info) }
    })
}

// ---------- sessions ----------

pub unsafe extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    _pApplication: CK_VOID_PTR,
    _Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        if flags & CKF_SERIAL_SESSION == 0 {
            return Err(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
        }
        token_name(&p, slotID)?;
        if phSession.is_null() {
            return Err(CKR_ARGUMENTS_BAD);
        }
        let h = p.open_session(slotID, flags);
        // SAFETY: phSession checked non-null; valid per the C_OpenSession contract.
        unsafe { put(phSession, h) }
    })
}

pub unsafe extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        let removed = p.lock_sessions().remove(&hSession);
        removed.map(|_| ()).ok_or(CKR_SESSION_HANDLE_INVALID)
    })
}

pub unsafe extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        token_name(&p, slotID)?;
        p.lock_sessions().retain(|_, s| s.slot != slotID);
        Ok(())
    })
}

fn session_slot(p: &Provider, h: CK_SESSION_HANDLE) -> Result<CK_SLOT_ID, Rv> {
    p.lock_sessions()
        .get(&h)
        .map(|s| s.slot)
        .ok_or(CKR_SESSION_HANDLE_INVALID)
}

pub unsafe extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: CK_SESSION_INFO_PTR,
) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        let (slot, flags) = p
            .lock_sessions()
            .get(&hSession)
            .map(|s| (s.slot, s.flags))
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        let state = if flags & CKF_RW_SESSION != 0 {
            CKS_RW_PUBLIC_SESSION
        } else {
            CKS_RO_PUBLIC_SESSION
        };
        let info = CK_SESSION_INFO {
            slotID: slot,
            state,
            flags,
            ulDeviceError: 0,
        };
        // SAFETY: pInfo is null or valid for a CK_SESSION_INFO write.
        unsafe { put(pInfo, info) }
    })
}

/// Accepted and discarded: the PIN belongs to the approver, never to this host.
pub unsafe extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    _userType: CK_USER_TYPE,
    _pPin: CK_UTF8CHAR_PTR,
    _ulPinLen: CK_ULONG,
) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        session_slot(&p, hSession).map(|_| ())
    })
}

pub unsafe extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        session_slot(&p, hSession).map(|_| ())
    })
}

// ---------- objects ----------

pub unsafe extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        let slot = session_slot(&p, hSession)?;
        // SAFETY: per the C_FindObjectsInit contract.
        let tpl = unsafe { template(pTemplate, ulCount) }?;
        let found: Vec<CK_OBJECT_HANDLE> = p
            .objects(slot)
            .iter()
            .filter(|o| o.matches(&tpl))
            .map(|o| o.handle)
            .collect();
        let mut sessions = p.lock_sessions();
        let s = sessions
            .get_mut(&hSession)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        if s.find.is_some() {
            return Err(CKR_OPERATION_ACTIVE);
        }
        s.find = Some(found);
        Ok(())
    })
}

pub unsafe extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        if pulObjectCount.is_null() || (phObject.is_null() && ulMaxObjectCount > 0) {
            return Err(CKR_ARGUMENTS_BAD);
        }
        let mut sessions = p.lock_sessions();
        let s = sessions
            .get_mut(&hSession)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        let found = s.find.as_mut().ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        let n = found.len().min(ulMaxObjectCount as usize);
        let batch: Vec<CK_OBJECT_HANDLE> = found.drain(..n).collect();
        if n > 0 {
            // SAFETY: phObject is valid for ulMaxObjectCount >= n handles.
            unsafe { std::ptr::copy_nonoverlapping(batch.as_ptr(), phObject, n) };
        }
        // SAFETY: pulObjectCount checked non-null above.
        unsafe { put(pulObjectCount, n as CK_ULONG) }
    })
}

pub unsafe extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        let mut sessions = p.lock_sessions();
        let s = sessions
            .get_mut(&hSession)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        s.find
            .take()
            .map(|_| ())
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)
    })
}

pub unsafe extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        let slot = session_slot(&p, hSession)?;
        let obj = p.object(slot, hObject).ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if ulCount > 0 && pTemplate.is_null() {
            return Err(CKR_ARGUMENTS_BAD);
        }
        // SAFETY: pTemplate holds ulCount attributes the caller lets us update in place.
        let attrs = unsafe { std::slice::from_raw_parts_mut(pTemplate, ulCount as usize) };
        let mut result = CKR_OK;
        for a in attrs.iter_mut() {
            match obj.attribute(a.type_) {
                Attr::Value(v) => {
                    if a.pValue.is_null() {
                        a.ulValueLen = v.len() as CK_ULONG;
                    } else if (a.ulValueLen as usize) < v.len() {
                        a.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                        result = CKR_BUFFER_TOO_SMALL;
                    } else {
                        // SAFETY: pValue is valid for ulValueLen >= v.len() bytes.
                        unsafe {
                            std::ptr::copy_nonoverlapping(v.as_ptr(), a.pValue as *mut u8, v.len())
                        };
                        a.ulValueLen = v.len() as CK_ULONG;
                    }
                }
                Attr::Sensitive => {
                    a.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    result = CKR_ATTRIBUTE_SENSITIVE;
                }
                Attr::Invalid => {
                    a.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    result = CKR_ATTRIBUTE_TYPE_INVALID;
                }
            }
        }
        if result == CKR_OK {
            Ok(())
        } else {
            Err(result)
        }
    })
}

// ---------- operations ----------

/// Parse a CK_MECHANISM (with OAEP parameters) through the core's mapping.
///
/// SAFETY (for callers): `m` null or a valid CK_MECHANISM whose parameter matches its type.
unsafe fn mechanism(m: CK_MECHANISM_PTR) -> Result<Mechanism, Rv> {
    if m.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // SAFETY: non-null and valid per the caller's contract.
    let m = unsafe { &*m };
    let oaep = if m.mechanism == CKM_RSA_PKCS_OAEP {
        if m.pParameter.is_null()
            || (m.ulParameterLen as usize) < std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>()
        {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }
        // SAFETY: the parameter is a CK_RSA_PKCS_OAEP_PARAMS of the checked size.
        let p = unsafe { &*(m.pParameter as *const CK_RSA_PKCS_OAEP_PARAMS) };
        let label = if p.source == CKZ_DATA_SPECIFIED {
            // SAFETY: pSourceData holds ulSourceDataLen bytes.
            unsafe { bytes(p.pSourceData as *const u8, p.ulSourceDataLen) }?.to_vec()
        } else if p.source == 0 && p.ulSourceDataLen == 0 {
            Vec::new()
        } else {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        };
        Some(OaepParams {
            hash_alg: p.hashAlg as u64,
            mgf: p.mgf as u64,
            label,
        })
    } else {
        None
    };
    Mechanism::from_pkcs11(m.mechanism as u64, oaep).map_err(|e| rv(&e))
}

fn op_init(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
    op: Op,
) -> Result<(), Rv> {
    let p = need_provider()?;
    let slot = session_slot(&p, hSession)?;
    // SAFETY: per the C_SignInit / C_DecryptInit contract.
    let mech = unsafe { mechanism(pMechanism) }?;
    let obj = p.object(slot, hKey).ok_or(CKR_KEY_HANDLE_INVALID)?;
    if obj.public {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    // Rejected locally, before anything is sent (Failure handling rows 4 and 5).
    check_key_mechanism(obj.key.role, obj.key.algorithm, op, &mech).map_err(|e| {
        log::info(&format!(
            "refused {} with {} on {}: {e}",
            op.as_str(),
            mech.name(),
            obj.key.label
        ));
        rv(&e)
    })?;
    let mut sessions = p.lock_sessions();
    let s = sessions
        .get_mut(&hSession)
        .ok_or(CKR_SESSION_HANDLE_INVALID)?;
    let slot_ref = match op {
        Op::Sign => &mut s.sign,
        Op::Decrypt => &mut s.decrypt,
    };
    if slot_ref.is_some() {
        return Err(CKR_OPERATION_ACTIVE);
    }
    *slot_ref = Some(Operation {
        op,
        key: obj.key,
        mechanism: mech,
        data: Vec::new(),
        result: None,
        busy: false,
    });
    Ok(())
}

fn op_mut(s: &mut crate::provider::Session, op: Op) -> &mut Option<Operation> {
    match op {
        Op::Sign => &mut s.sign,
        Op::Decrypt => &mut s.decrypt,
    }
}

/// Run the operation once (unless a result is cached), then deliver with the two-call
/// convention: a length query or a short buffer keeps the cached result for the next call;
/// a successful copy or any other error ends the operation.
///
/// SAFETY (for callers): `out` null or valid for `*out_len` bytes; `out_len` valid.
unsafe fn finish(
    hSession: CK_SESSION_HANDLE,
    op: Op,
    final_input: Option<Vec<u8>>,
    out: *mut u8,
    out_len: *mut CK_ULONG,
) -> Result<(), Rv> {
    if out_len.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let p = need_provider()?;
    let pending = {
        let mut sessions = p.lock_sessions();
        let s = sessions
            .get_mut(&hSession)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        let o = op_mut(s, op)
            .as_mut()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if o.busy {
            return Err(CKR_OPERATION_ACTIVE);
        }
        if o.result.is_none() {
            if let Some(d) = final_input {
                o.data = d;
            }
            o.busy = true;
            Some((
                o.key.clone(),
                o.mechanism.clone(),
                std::mem::take(&mut o.data),
            ))
        } else {
            None
        }
    };
    // The approval wait happens without holding any lock, so other sessions proceed.
    if let Some((key, mech, data)) = pending {
        let r = p.run(op, &key, mech, data);
        let mut sessions = p.lock_sessions();
        let s = sessions
            .get_mut(&hSession)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        match r {
            Ok(result) => {
                let o = op_mut(s, op)
                    .as_mut()
                    .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
                o.result = Some(result);
                o.busy = false;
            }
            Err(e) => {
                *op_mut(s, op) = None;
                return Err(e);
            }
        }
    }
    let mut sessions = p.lock_sessions();
    let s = sessions
        .get_mut(&hSession)
        .ok_or(CKR_SESSION_HANDLE_INVALID)?;
    let slot_ref = op_mut(s, op);
    let result: Zeroizing<Vec<u8>> = slot_ref
        .as_ref()
        .and_then(|o| o.result.clone())
        .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
    // SAFETY: out_len checked non-null above.
    let have = unsafe { *out_len } as usize;
    // SAFETY: as above.
    unsafe { *out_len = result.len() as CK_ULONG };
    if out.is_null() {
        return Ok(()); // length query: serve the real call from the cache
    }
    if have < result.len() {
        return Err(CKR_BUFFER_TOO_SMALL); // keep the result cached for the session
    }
    // SAFETY: out is valid for have >= result.len() bytes.
    unsafe { std::ptr::copy_nonoverlapping(result.as_ptr(), out, result.len()) };
    *slot_ref = None;
    Ok(())
}

pub unsafe extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    guard(|| op_init(hSession, pMechanism, hKey, Op::Sign))
}

pub unsafe extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        // SAFETY: pData holds ulDataLen bytes per the C_Sign contract.
        let data = unsafe { bytes(pData, ulDataLen) }?.to_vec();
        // SAFETY: per the C_Sign contract for the output buffer.
        unsafe { finish(hSession, Op::Sign, Some(data), pSignature, pulSignatureLen) }
    })
}

pub unsafe extern "C" fn C_SignUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        // SAFETY: pPart holds ulPartLen bytes.
        let part = unsafe { bytes(pPart, ulPartLen) }?;
        let mut sessions = p.lock_sessions();
        let s = sessions
            .get_mut(&hSession)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        let o = s.sign.as_mut().ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        // Raw mechanisms are single-part in PKCS#11, but callers such as pkcs11-tool retry a
        // failed C_Sign as Update/Final; buffering keeps their real error code visible. The
        // length limits still apply when the request is built.
        if o.result.is_some() {
            s.sign = None;
            return Err(CKR_OPERATION_ACTIVE);
        }
        if o.data.len() + part.len() > MAX_SIGN_MESSAGE_LEN {
            s.sign = None;
            return Err(CKR_DATA_LEN_RANGE);
        }
        o.data.extend_from_slice(part);
        Ok(())
    })
}

pub unsafe extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    // SAFETY: per the C_SignFinal contract for the output buffer.
    guard(|| unsafe { finish(hSession, Op::Sign, None, pSignature, pulSignatureLen) })
}

pub unsafe extern "C" fn C_DecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    guard(|| op_init(hSession, pMechanism, hKey, Op::Decrypt))
}

pub unsafe extern "C" fn C_Decrypt(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        // SAFETY: pEncryptedData holds ulEncryptedDataLen bytes.
        let data = unsafe { bytes(pEncryptedData, ulEncryptedDataLen) }?.to_vec();
        // SAFETY: per the C_Decrypt contract for the output buffer.
        unsafe { finish(hSession, Op::Decrypt, Some(data), pData, pulDataLen) }
    })
}

/// Encryption runs in software with the public key (spec: role table, `encrypt`): it reveals
/// nothing, so it needs neither the relay nor an approval.
pub unsafe extern "C" fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    guard(|| {
        let p = need_provider()?;
        let slot = session_slot(&p, hSession)?;
        // SAFETY: per the C_EncryptInit contract.
        let mech = unsafe { mechanism(pMechanism) }?;
        let obj = p.object(slot, hKey).ok_or(CKR_KEY_HANDLE_INVALID)?;
        if !obj.public {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
        }
        check_encrypt(obj.key.role, obj.key.algorithm, &mech).map_err(|e| rv(&e))?;
        let Mechanism::RsaPkcsOaep { label } = mech else {
            return Err(CKR_MECHANISM_INVALID);
        };
        let mut sessions = p.lock_sessions();
        let s = sessions
            .get_mut(&hSession)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        if s.encrypt.is_some() {
            return Err(CKR_OPERATION_ACTIVE);
        }
        s.encrypt = Some((obj.key, label));
        Ok(())
    })
}

pub unsafe extern "C" fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR,
) -> CK_RV {
    guard(|| {
        if pulEncryptedDataLen.is_null() {
            return Err(CKR_ARGUMENTS_BAD);
        }
        let p = need_provider()?;
        let mut sessions = p.lock_sessions();
        let s = sessions
            .get_mut(&hSession)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        let (key, label) = s.encrypt.clone().ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        let k = key
            .algorithm
            .rsa_modulus_len()
            .ok_or(CKR_KEY_FUNCTION_NOT_PERMITTED)?;
        // SAFETY: pData holds ulDataLen bytes.
        let data = unsafe { bytes(pData, ulDataLen) }?;
        if data.len() > relay_core::mechanism::oaep_max_plaintext(k) {
            s.encrypt = None;
            return Err(CKR_DATA_LEN_RANGE);
        }
        // SAFETY: pulEncryptedDataLen checked non-null.
        let have = unsafe { *pulEncryptedDataLen } as usize;
        // SAFETY: as above.
        unsafe { *pulEncryptedDataLen = k as CK_ULONG };
        if pEncryptedData.is_null() {
            return Ok(()); // length query: the ciphertext is always k bytes
        }
        if have < k {
            return Err(CKR_BUFFER_TOO_SMALL);
        }
        s.encrypt = None;
        let ct = relay_core::padding::encrypt_oaep_sha256(&key.public_key, &label, data)
            .map_err(|e| rv(&e))?;
        // SAFETY: pEncryptedData is valid for have >= k == ct.len() bytes.
        unsafe { std::ptr::copy_nonoverlapping(ct.as_ptr(), pEncryptedData, ct.len()) };
        Ok(())
    })
}
