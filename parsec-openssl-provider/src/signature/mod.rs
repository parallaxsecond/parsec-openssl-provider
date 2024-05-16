// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::keymgmt::ParsecProviderKeyObject;
use crate::openssl_bindings::*;
use crate::{
    PARSEC_PROVIDER_DESCRIPTION_ECDSA, PARSEC_PROVIDER_DESCRIPTION_RSA,
    PARSEC_PROVIDER_DFLT_PROPERTIES, PARSEC_PROVIDER_ECDSA_NAME, PARSEC_PROVIDER_RSA_NAME,
};
use parsec_client::core::interface::operations::psa_algorithm::Algorithm;
use parsec_client::core::interface::operations::psa_algorithm::Hash;
use parsec_client::core::interface::operations::psa_key_attributes::{Attributes, EccFamily, Type};
use parsec_openssl2::types::VOID_PTR;
use parsec_openssl2::*;
use picky_asn1::wrapper::IntegerAsn1;
use serde::{Deserialize, Serialize};
use std::ffi::CStr;
use std::sync::{Arc, RwLock};

#[derive(Serialize, Deserialize)]
struct EccSignature {
    r: IntegerAsn1,
    s: IntegerAsn1,
}

struct ParsecProviderSignatureContext {
    /* The key object is set in the signature context by calling OSSL_FUNC_signature_sign_init().
    Before calling OSSL_FUNC_signature_sign_init(), the key object itself should have been set up
    and initialized via keymgmt function calls.
    */
    keyobj: Option<Arc<RwLock<ParsecProviderKeyObject>>>,
}

impl ParsecProviderSignatureContext {
    pub fn new() -> Self {
        ParsecProviderSignatureContext { keyobj: None }
    }
}

/*
Should create and return a pointer to a provider side structure for holding context information during a
signature operation. A pointer to this context will be passed back in a number of the other signature operation
function calls.
The parameter provctx is the provider context generated during provider initialisation.
The propq parameter is a property query string that may be (optionally) used by the provider during any "fetches" that
it may perform (if it performs any).
*/
pub unsafe extern "C" fn parsec_provider_signature_newctx(
    _provctx: VOID_PTR,
    _propq: *const std::os::raw::c_char,
) -> VOID_PTR {
    // We are currently ignoring provctx and propq, so no need for input validation (checking for NULL, etc.)

    let new_context = Arc::new(RwLock::new(ParsecProviderSignatureContext::new()));

    Arc::into_raw(new_context) as VOID_PTR
}

// should free any resources associated with the provider side signature context
pub unsafe extern "C" fn parsec_provider_signature_freectx(ctx: VOID_PTR) {
    if ctx.is_null() {
        return;
    }

    let sig_ctx = Arc::from_raw(ctx as *const RwLock<ParsecProviderSignatureContext>);
    // A strong_count of 1 should be guaranteed by OPENSSL, as it doesn't make sense to be calling
    // free when you are still using the ctx.
    assert_eq!(1, Arc::strong_count(&sig_ctx));
    // When sig_ctx is dropped, the reference count is decremented and the memory is freed
}

fn get_signature_len(key_attrs: Attributes) -> Result<usize, String> {
    match key_attrs.key_type {
        Type::RsaKeyPair => Ok(key_attrs.bits / 8),
        Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        } => {
            let size_times_two: usize = key_attrs.bits * 2;
            Ok(size_times_two.div_ceil(8))
        }
        _ => Err("Key type not recognized".to_string()),
    }
}

/*
implements a "one shot" digest sign operation previously started through
OSSL_FUNC_signature_digeset_sign_init(). A previously initialised signature
context is passed in the ctx parameter. The data to be signed is in tbs which
should be tbslen bytes long.
*/
unsafe extern "C" fn parsec_provider_signature_digest_sign(
    ctx: VOID_PTR,
    sig: *mut std::os::raw::c_uchar,
    siglen: *mut std::os::raw::c_uint,
    sigsize: std::os::raw::c_uint,
    tbs: *const std::os::raw::c_uchar,
    tbslen: std::os::raw::c_uint,
) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_SIGNATURE_DIGEST_SIGN), || {
        if ctx.is_null() || siglen.is_null() {
            return Err("Received unexpected NULL pointer as an argument.".into());
        }

        Arc::increment_strong_count(ctx as *const RwLock<ParsecProviderSignatureContext>);
        let sig_ctx = Arc::from_raw(ctx as *const RwLock<ParsecProviderSignatureContext>);

        let reader_sig_ctx = sig_ctx.read().unwrap();
        let key_data = match reader_sig_ctx.keyobj {
            None => {
                return Err("Key Object not set. This should be done through sign_init()".into())
            }
            Some(ref keyobj) => keyobj.read().unwrap(),
        };

        let key_name = match key_data.get_key_name() {
            None => return Err("Key name not set in the Key Object".into()),
            Some(ref name) => name,
        };

        let key_attributes = key_data
            .get_provctx()
            .get_client()
            .key_attributes(key_name)
            .map_err(|e| format!("Failed to get specified key's attributes: {}", e))?;
        let siglength = get_signature_len(key_attributes).map_err(|e| {
            format!(
                "Failed to Get correct signature length for the given key:  {}",
                e
            )
        })?;

        if sig.is_null() {
            *siglen = siglength as std::os::raw::c_uint;
            return Ok(OPENSSL_SUCCESS);
        }

        if (sigsize as usize) < siglength {
            return Err(format!(
                "Signature length is bigger than sigsize. Signature length: {}",
                siglength
            )
            .into());
        }

        if tbs.is_null() {
            return Err("Received unexpected NULL pointer as an argument.".into());
        }

        let tbs_slice: &[u8] = core::slice::from_raw_parts(tbs, tbslen as usize);

        let sign_algorithm = match key_attributes.policy.permitted_algorithms {
            Algorithm::AsymmetricSignature(signature_algo) => signature_algo,
            _ => {
                return Err(
                    "Specified key does not permit the AsymmetricSignature algorithm".into(),
                )
            }
        };

        let hash_res: Vec<u8> = key_data
            .get_provctx()
            .get_client()
            .psa_hash_compute(Hash::Sha256, tbs_slice)
            .map_err(|e| format!("Parsec Client failed to hash: {:?}", e))?;

        let mut sign_res: Vec<u8> = key_data
            .get_provctx()
            .get_client()
            .psa_sign_hash(key_name, &hash_res, sign_algorithm)
            .map_err(|e| format!("Parsec Client failed to sign: {:?}", e))?;

        if sign_algorithm.is_ecc_alg() {
            let s = IntegerAsn1::from_bytes_be_unsigned(sign_res.split_off(sign_res.len() / 2));
            sign_res = picky_asn1_der::to_vec(&EccSignature {
                r: IntegerAsn1::from_bytes_be_unsigned(sign_res),
                s,
            })
            .map_err(|e| format!("Failed to convert ECC Signature: {:?}", e))?;
        }
        std::ptr::copy(sign_res.as_ptr(), sig, sign_res.len());
        *siglen = sign_res.len() as u32;
        Ok(OPENSSL_SUCCESS)
    });

    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
}

unsafe extern "C" fn parsec_provider_signature_digest_sign_init(
    ctx: VOID_PTR,
    mdname: *const std::os::raw::c_char,
    provkey: VOID_PTR,
    params: *const OSSL_PARAM,
) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_SIGNATURE_DIGEST_SIGN_INIT), || {
        if ctx.is_null() || provkey.is_null() {
            return Err("Neither ctx nor provkey pointers should be NULL.".into());
        }

        Arc::increment_strong_count(ctx as *const RwLock<ParsecProviderSignatureContext>);
        let sig_ctx = Arc::from_raw(ctx as *const RwLock<ParsecProviderSignatureContext>);
        let mut writer_sig_ctx = sig_ctx.write().unwrap();
        Arc::increment_strong_count(provkey as *const RwLock<ParsecProviderKeyObject>);
        let prov_key = Arc::from_raw(provkey as *const RwLock<ParsecProviderKeyObject>);

        writer_sig_ctx.keyobj = Some(prov_key.clone());
        let key_data = match writer_sig_ctx.keyobj {
            None => {
                return Err("Key Object not set.".into())
            }
            Some(ref keyobj) => keyobj.read().unwrap(),
        };

        let key_name = match key_data.get_key_name() {
            None => return Err("Key name not set in the Key Object".into()),
            Some(ref name) => name,
        };
        // Currently we only support SHA256 hash function.
        // Return error if any other function is selected.
        if let Ok(hash_function) = CStr::from_ptr(mdname).to_str() {
            if hash_function != "SHA256" && hash_function != "SHA2-256" {
                return Err("Invalid hash function".into());
            }
        }
        let key_attributes = key_data
            .get_provctx()
            .get_client()
            .key_attributes(key_name)
            .map_err(|e| format!("Failed to get specified key's attributes: {}", e))?;
        match key_attributes.key_type {
            Type::RsaKeyPair => Ok(parsec_provider_signature_rsa_set_params(ctx, params)),
            Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            } => Ok(parsec_provider_signature_ecdsa_set_params(ctx, params)),
            _ => Err("Key type not recognized".to_string().into()),
        }
    });

    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
}

unsafe extern "C" fn parsec_provider_signature_rsa_settable_params(
    _ctx: VOID_PTR,
    _provkey: VOID_PTR,
) -> *const OSSL_PARAM {
    static ONCE_INIT: std::sync::Once = std::sync::Once::new();
    static mut SIGCTX_SETTABLE_TABLE: [OSSL_PARAM; 3] = [ossl_param!(); 3];

    ONCE_INIT.call_once(|| {
        SIGCTX_SETTABLE_TABLE = [
            ossl_param!(OSSL_SIGNATURE_PARAM_PAD_MODE, OSSL_PARAM_UTF8_STRING),
            ossl_param!(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, OSSL_PARAM_UTF8_STRING),
            ossl_param!(),
        ];
    });
    SIGCTX_SETTABLE_TABLE.as_ptr() as _
}

unsafe extern "C" fn parsec_provider_signature_ecdsa_settable_params(
    _ctx: VOID_PTR,
    _provkey: VOID_PTR,
) -> *const OSSL_PARAM {
    static ONCE_INIT: std::sync::Once = std::sync::Once::new();
    static mut SIGCTX_SETTABLE_TABLE: [OSSL_PARAM; 1] = [ossl_param!(); 1];

    ONCE_INIT.call_once(|| {
        SIGCTX_SETTABLE_TABLE = [ossl_param!()];
    });
    SIGCTX_SETTABLE_TABLE.as_ptr() as _
}

/*
Sets the context parameters for ECDSA signature
*/
pub unsafe extern "C" fn parsec_provider_signature_ecdsa_set_params(
    _keydata: VOID_PTR,
    _params: *const OSSL_PARAM,
) -> std::os::raw::c_int {
    OPENSSL_SUCCESS
}

/*
Sets the context parameters for RSA signature
*/
pub unsafe extern "C" fn parsec_provider_signature_rsa_set_params(
    _keydata: VOID_PTR,
    params: *const OSSL_PARAM,
) -> std::os::raw::c_int {
    // Currently we only support PSS paddding mode with a Salt length of 32 bytes equivalent to the
    // hash length. So we only check for these values here and not update the signature context
    // object with it.

    // Check the padding mode
    if let Ok(param) = openssl_returns_nonnull_const(openssl_bindings::OSSL_PARAM_locate_const(
        params,
        OSSL_SIGNATURE_PARAM_PAD_MODE.as_ptr() as _,
    )) {
        if (*param).data_type == OSSL_PARAM_UTF8_STRING {
            let pad_mode: &[u8] =
                core::slice::from_raw_parts((*param).data as *mut u8, (*param).data_size);
            if pad_mode != OSSL_PKEY_RSA_PAD_MODE_PSS {
                return OPENSSL_ERROR;
            }
        }
        if (*param).data_type == OSSL_PARAM_INTEGER {
            let pad_mode: &[u8] =
                core::slice::from_raw_parts((*param).data as *mut u8, (*param).data_size);
            if pad_mode[0] != 6 {
                return OPENSSL_ERROR;
            }
        }
    }

    // Check the salt length
    if let Ok(param) = openssl_returns_nonnull_const(openssl_bindings::OSSL_PARAM_locate_const(
        params,
        OSSL_SIGNATURE_PARAM_PSS_SALTLEN.as_ptr() as _,
    )) {
        if (*param).data_type == OSSL_PARAM_UTF8_STRING {
            let salt_len: &[u8] =
                core::slice::from_raw_parts((*param).data as *const u8, (*param).data_size);
            if *salt_len != OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST[..6] {
                return OPENSSL_ERROR;
            }
        }
        if (*param).data_type == OSSL_PARAM_INTEGER {
            let salt_len: &mut [u8] =
                core::slice::from_raw_parts_mut((*param).data as *mut u8, (*param).data_size);
            if salt_len[0] != 32 {
                return OPENSSL_ERROR;
            }
        }
    }

    OPENSSL_SUCCESS
}

pub type SignatureNewCtxPtr =
    unsafe extern "C" fn(VOID_PTR, *const std::os::raw::c_char) -> VOID_PTR;
pub type SignatureFreeCtxPtr = unsafe extern "C" fn(VOID_PTR);
pub type SignatureDigestSignPtr = unsafe extern "C" fn(
    VOID_PTR,
    *mut std::os::raw::c_uchar,
    *mut std::os::raw::c_uint,
    std::os::raw::c_uint,
    *const std::os::raw::c_uchar,
    std::os::raw::c_uint,
) -> std::os::raw::c_int;

pub type SignatureDigestSignInitPtr = unsafe extern "C" fn(
    VOID_PTR,
    *const std::os::raw::c_char,
    VOID_PTR,
    *const OSSL_PARAM,
) -> std::os::raw::c_int;

const OSSL_FUNC_SIGNATURE_RSA_SETTABLE_PARAMS_PTR: SignatureSettableParamsPtr =
    parsec_provider_signature_rsa_settable_params;
const OSSL_FUNC_SIGNATURE_ECDSA_SETTABLE_PARAMS_PTR: SignatureSettableParamsPtr =
    parsec_provider_signature_ecdsa_settable_params;
const OSSL_FUNC_SIGNATURE_RSA_SET_PARAMS_PTR: SignatureSetParamsPtr =
    parsec_provider_signature_rsa_set_params;
const OSSL_FUNC_SIGNATURE_ECDSA_SET_PARAMS_PTR: SignatureSetParamsPtr =
    parsec_provider_signature_ecdsa_set_params;
pub type SignatureSettableParamsPtr = unsafe extern "C" fn(VOID_PTR, VOID_PTR) -> *const OSSL_PARAM;

pub type SignatureSetParamsPtr =
    unsafe extern "C" fn(VOID_PTR, *const OSSL_PARAM) -> std::os::raw::c_int;

const OSSL_FUNC_SIGNATURE_NEWCTX_PTR: SignatureNewCtxPtr = parsec_provider_signature_newctx;
const OSSL_FUNC_SIGNATURE_FREECTX_PTR: SignatureFreeCtxPtr = parsec_provider_signature_freectx;
const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_PTR: SignatureDigestSignPtr =
    parsec_provider_signature_digest_sign;

const OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT_PTR: SignatureDigestSignInitPtr =
    parsec_provider_signature_digest_sign_init;

const PARSEC_PROVIDER_RSA_SIGN_IMPL: [OSSL_DISPATCH; 7] = [
    unsafe { ossl_dispatch!(OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_NEWCTX_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_FREECTX_PTR) },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_PTR
        )
    },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT_PTR
        )
    },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
            OSSL_FUNC_SIGNATURE_RSA_SETTABLE_PARAMS_PTR
        )
    },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
            OSSL_FUNC_SIGNATURE_RSA_SET_PARAMS_PTR
        )
    },
    ossl_dispatch!(),
];

const PARSEC_PROVIDER_SIGN_ECDSA_IMPL: [OSSL_DISPATCH; 7] = [
    unsafe { ossl_dispatch!(OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_NEWCTX_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_FREECTX_PTR) },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_PTR
        )
    },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
            OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT_PTR
        )
    },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
            OSSL_FUNC_SIGNATURE_ECDSA_SETTABLE_PARAMS_PTR
        )
    },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
            OSSL_FUNC_SIGNATURE_ECDSA_SET_PARAMS_PTR
        )
    },
    ossl_dispatch!(),
];

pub const PARSEC_PROVIDER_SIGNATURE: [OSSL_ALGORITHM; 3] = [
    ossl_algorithm!(
        PARSEC_PROVIDER_ECDSA_NAME,
        PARSEC_PROVIDER_DFLT_PROPERTIES,
        PARSEC_PROVIDER_SIGN_ECDSA_IMPL,
        PARSEC_PROVIDER_DESCRIPTION_ECDSA
    ),
    ossl_algorithm!(
        PARSEC_PROVIDER_RSA_NAME,
        PARSEC_PROVIDER_DFLT_PROPERTIES,
        PARSEC_PROVIDER_RSA_SIGN_IMPL,
        PARSEC_PROVIDER_DESCRIPTION_RSA
    ),
    ossl_algorithm!(),
];

#[test]
fn test_sign_newctx() {
    use crate::{parsec_provider_provider_init, parsec_provider_teardown};

    let out: *const OSSL_DISPATCH = std::ptr::null();
    let mut provctx: types::VOID_PTR = std::ptr::null_mut();

    // Initialize the provider
    let result: Result<(), parsec_openssl2::Error> = unsafe {
        parsec_provider_provider_init(
            std::ptr::null(),
            std::ptr::null(),
            &out as *const _ as *mut _,
            &mut provctx as *mut VOID_PTR,
        )
    };
    assert!(result.is_ok());
    assert_ne!(provctx, std::ptr::null_mut());
    let s = String::from("");

    let sig_ctx = unsafe { parsec_provider_signature_newctx(provctx, s.as_ptr() as _) };
    assert_ne!(sig_ctx, std::ptr::null_mut());

    unsafe {
        parsec_provider_signature_freectx(sig_ctx);
        parsec_provider_teardown(provctx as _);
    }
}
