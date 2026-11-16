//! Generated from cryptoki-sys 0.5.0's `CK_C_*` types: every PKCS#11 v2.40 function this
//! provider does not implement returns `CKR_FUNCTION_NOT_SUPPORTED`. Regenerate if the
//! function list changes.
#![allow(non_snake_case, clippy::missing_safety_doc)]

use cryptoki_sys::*;

pub unsafe extern "C" fn C_InitToken(
    _arg1: CK_SLOT_ID,
    _arg2: *mut CK_UTF8CHAR,
    _arg3: CK_ULONG,
    _arg4: *mut CK_UTF8CHAR,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_InitPIN(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_UTF8CHAR,
    _arg3: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SetPIN(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_UTF8CHAR,
    _arg3: CK_ULONG,
    _arg4: *mut CK_UTF8CHAR,
    _arg5: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_GetOperationState(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SetOperationState(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: CK_OBJECT_HANDLE,
    _arg5: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_CreateObject(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_ATTRIBUTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_CopyObject(
    _arg1: CK_SESSION_HANDLE,
    _arg2: CK_OBJECT_HANDLE,
    _arg3: *mut CK_ATTRIBUTE,
    _arg4: CK_ULONG,
    _arg5: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DestroyObject(
    _arg1: CK_SESSION_HANDLE,
    _arg2: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_GetObjectSize(
    _arg1: CK_SESSION_HANDLE,
    _arg2: CK_OBJECT_HANDLE,
    _arg3: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SetAttributeValue(
    _arg1: CK_SESSION_HANDLE,
    _arg2: CK_OBJECT_HANDLE,
    _arg3: *mut CK_ATTRIBUTE,
    _arg4: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_EncryptUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_EncryptFinal(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DecryptUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DecryptFinal(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DigestInit(_arg1: CK_SESSION_HANDLE, _arg2: *mut CK_MECHANISM) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_Digest(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DigestUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DigestKey(_arg1: CK_SESSION_HANDLE, _arg2: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DigestFinal(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SignRecoverInit(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SignRecover(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_VerifyInit(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_Verify(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_VerifyUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_VerifyFinal(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_VerifyRecoverInit(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_VerifyRecover(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DigestEncryptUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DecryptDigestUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SignEncryptUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DecryptVerifyUpdate(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
    _arg4: *mut CK_BYTE,
    _arg5: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_GenerateKey(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: *mut CK_ATTRIBUTE,
    _arg4: CK_ULONG,
    _arg5: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_GenerateKeyPair(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: *mut CK_ATTRIBUTE,
    _arg4: CK_ULONG,
    _arg5: *mut CK_ATTRIBUTE,
    _arg6: CK_ULONG,
    _arg7: *mut CK_OBJECT_HANDLE,
    _arg8: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_WrapKey(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
    _arg4: CK_OBJECT_HANDLE,
    _arg5: *mut CK_BYTE,
    _arg6: *mut CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_UnwrapKey(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
    _arg4: *mut CK_BYTE,
    _arg5: CK_ULONG,
    _arg6: *mut CK_ATTRIBUTE,
    _arg7: CK_ULONG,
    _arg8: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_DeriveKey(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_MECHANISM,
    _arg3: CK_OBJECT_HANDLE,
    _arg4: *mut CK_ATTRIBUTE,
    _arg5: CK_ULONG,
    _arg6: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_SeedRandom(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_GenerateRandom(
    _arg1: CK_SESSION_HANDLE,
    _arg2: *mut CK_BYTE,
    _arg3: CK_ULONG,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_GetFunctionStatus(_arg1: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_CancelFunction(_arg1: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

pub unsafe extern "C" fn C_WaitForSlotEvent(
    _arg1: CK_FLAGS,
    _arg2: *mut CK_SLOT_ID,
    _arg3: *mut ::std::os::raw::c_void,
) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}
