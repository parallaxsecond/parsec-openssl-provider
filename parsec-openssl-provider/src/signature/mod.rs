// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::keymgmt::ParsecProviderKeyObject;
use crate::openssl_bindings::{
    OSSL_ALGORITHM, OSSL_DISPATCH, OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_FREECTX,
    OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_SIGN, OSSL_FUNC_SIGNATURE_SIGN_INIT,
    OSSL_PARAM,
};
use crate::{
    PARSEC_PROVIDER_DESCRIPTION_ECDSA, PARSEC_PROVIDER_DESCRIPTION_RSA,
    PARSEC_PROVIDER_DFLT_PROPERTIES, PARSEC_PROVIDER_ECDSA_NAME, PARSEC_PROVIDER_RSA_NAME,
};
use parsec_client::core::interface::operations::psa_algorithm::{AsymmetricSignature, Hash};
use parsec_openssl2::types::VOID_PTR;
use parsec_openssl2::*;

use std::sync::{Arc, Mutex};

struct ParsecProviderSignatureContext {
    /* The key object is set in the signature context by calling OSSL_FUNC_signature_sign_init().
    Before calling OSSL_FUNC_signature_sign_init(), the key object itself should have been set up
    and initialized via keymgmt function calls.
    */
    keyobj: Mutex<Option<Arc<ParsecProviderKeyObject>>>,
}

impl ParsecProviderSignatureContext {
    pub fn new() -> Self {
        ParsecProviderSignatureContext {
            keyobj: Mutex::new(None),
        }
    }
}

impl Clone for ParsecProviderSignatureContext {
    fn clone(&self) -> Self {
        let new_keyobj = (*(self.keyobj.lock().unwrap())).clone();
        ParsecProviderSignatureContext {
            keyobj: Mutex::new(new_keyobj),
        }
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

    let new_context = Arc::new(ParsecProviderSignatureContext::new());

    Arc::into_raw(new_context) as VOID_PTR
}

// should free any resources associated with the provider side signature context
pub unsafe extern "C" fn parsec_provider_signature_freectx(ctx: VOID_PTR) {
    if ctx.is_null() {
        return;
    }

    let ctx_ptr = ctx as *const ParsecProviderSignatureContext;
    let arc_ctx = Arc::from_raw(ctx_ptr);
    // A strong_count of 1 should be guaranteed by OPENSSL, as it doesn't make sense to be calling
    // free when you are still using the ctx.
    assert_eq!(1, Arc::strong_count(&arc_ctx));
    // When arc_ctx is dropped, the reference count is decremented and the memory is freed
}

/*
Initialises a context for signing given a provider side signature context in the ctx parameter, and a pointer to a
provider key object in the provkey parameter. The params, if not NULL, should be set on the context in a manner similar
to using OSSL_FUNC_signature_set_ctx_params(). The key object should have been previously generated, loaded or imported
into the provider using the key management (OSSL_OP_KEYMGMT) operation.
*/
unsafe extern "C" fn parsec_provider_signature_sign_init(
    ctx: VOID_PTR,
    provkey: VOID_PTR,
    _params: *const OSSL_PARAM,
) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_SIGNATURE_SIGN_INIT), || {
        if ctx.is_null() || provkey.is_null() {
            return Err("Neither ctx nor provkey pointers should be NULL.".into());
        }
        let sig_ctx_ptr = ctx as *const ParsecProviderSignatureContext;
        Arc::increment_strong_count(sig_ctx_ptr);
        let arc_sig_ctx = Arc::from_raw(sig_ctx_ptr);

        let provkey_ptr = provkey as *const ParsecProviderKeyObject;
        Arc::increment_strong_count(provkey_ptr);
        let arc_provkey = Arc::from_raw(provkey_ptr);

        *(arc_sig_ctx.keyobj.lock().unwrap()) = Some(arc_provkey.clone());
        Ok(OPENSSL_SUCCESS)
    });

    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
}

unsafe extern "C" fn parsec_provider_signature_sign(
    ctx: VOID_PTR,
    sig: *mut std::os::raw::c_uchar,
    siglen: *mut std::os::raw::c_uint,
    sigsize: std::os::raw::c_uint,
    tbs: *const std::os::raw::c_uchar,
    tbslen: std::os::raw::c_uint,
) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_SIGNATURE_SIGN), || {
        if ctx.is_null() || tbs.is_null() || sig.is_null() || siglen.is_null() {
            return Err("Received unexpected NULL pointer as an argument.".into());
        }

        Arc::increment_strong_count(ctx as *const ParsecProviderSignatureContext);
        let arc_sig_ctx = Arc::from_raw(ctx as *const ParsecProviderSignatureContext);

        let keyobj = match *arc_sig_ctx.keyobj.lock().unwrap() {
            None => {
                return Err("Key Object not set. This should be done through sign_init()".into())
            }
            Some(ref keyobj) => keyobj.clone(),
        };

        let key_name_binding = keyobj.get_key_name();
        let key_name = match *key_name_binding {
            None => return Err("Key name not set in the Key Object".into()),
            Some(ref name) => name,
        };

        let tbs_slice: &[u8] = core::slice::from_raw_parts(tbs, tbslen as usize);

        let sign_algorithm = AsymmetricSignature::RsaPkcs1v15Sign {
            hash_alg: Hash::Sha256.into(),
        };

        let sign_res: Vec<u8> = keyobj
            .get_provctx()
            .get_client()
            .psa_sign_hash(key_name, tbs_slice, sign_algorithm)
            .map_err(|_| "Parsec Client failed to sign".to_string())?;

        if sigsize > sign_res.len() as u32 {
            std::ptr::copy(sign_res.as_ptr(), sig, sign_res.len());
        } else {
            std::ptr::copy(sign_res.as_ptr(), sig, sigsize as usize);
        }

        *siglen = sign_res.len() as u32;

        Ok(OPENSSL_SUCCESS)
    });

    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
}

/*
should duplicate the provider side signature context in the ctx parameter and return the duplicate copy
*/
pub unsafe extern "C" fn parsec_provider_signature_dupctx(ctx: VOID_PTR) -> VOID_PTR {
    if ctx.is_null() {
        return std::ptr::null_mut();
    }

    let ctx_ptr = ctx as *const ParsecProviderSignatureContext;
    Arc::increment_strong_count(ctx_ptr);
    let arc_ctx = Arc::from_raw(ctx_ptr);

    let duplicate: ParsecProviderSignatureContext = (*arc_ctx).clone();
    Arc::into_raw(Arc::new(duplicate)) as VOID_PTR
}

pub type SignatureNewCtxPtr =
    unsafe extern "C" fn(VOID_PTR, *const std::os::raw::c_char) -> VOID_PTR;
pub type SignatureFreeCtxPtr = unsafe extern "C" fn(VOID_PTR);
pub type SignatureDupCtxPtr = unsafe extern "C" fn(VOID_PTR) -> VOID_PTR;
pub type SignatureSignPtr = unsafe extern "C" fn(
    VOID_PTR,
    *mut std::os::raw::c_uchar,
    *mut std::os::raw::c_uint,
    std::os::raw::c_uint,
    *const std::os::raw::c_uchar,
    std::os::raw::c_uint,
) -> std::os::raw::c_int;
pub type SignatureSignInitPtr =
    unsafe extern "C" fn(VOID_PTR, VOID_PTR, *const OSSL_PARAM) -> std::os::raw::c_int;

const OSSL_FUNC_SIGNATURE_NEWCTX_PTR: SignatureNewCtxPtr = parsec_provider_signature_newctx;
const OSSL_FUNC_SIGNATURE_FREECTX_PTR: SignatureFreeCtxPtr = parsec_provider_signature_freectx;
const OSSL_FUNC_SIGNATURE_DUPCTX_PTR: SignatureDupCtxPtr = parsec_provider_signature_dupctx;
const OSSL_FUNC_SIGNATURE_SIGN_PTR: SignatureSignPtr = parsec_provider_signature_sign;
const OSSL_FUNC_SIGNATURE_SIGN_INIT_PTR: SignatureSignInitPtr = parsec_provider_signature_sign_init;

const PARSEC_PROVIDER_ECDSA_SIGN_IMPL: [OSSL_DISPATCH; 1] = [ossl_dispatch!()];
const PARSEC_PROVIDER_RSA_SIGN_IMPL: [OSSL_DISPATCH; 6] = [
    unsafe { ossl_dispatch!(OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_NEWCTX_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_FREECTX_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_SIGNATURE_DUPCTX, OSSL_FUNC_SIGNATURE_DUPCTX_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_SIGNATURE_SIGN, OSSL_FUNC_SIGNATURE_SIGN_PTR) },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_SIGNATURE_SIGN_INIT,
            OSSL_FUNC_SIGNATURE_SIGN_INIT_PTR
        )
    },
    ossl_dispatch!(),
];

pub const PARSEC_PROVIDER_SIGNATURE: [OSSL_ALGORITHM; 3] = [
    ossl_algorithm!(
        PARSEC_PROVIDER_ECDSA_NAME,
        PARSEC_PROVIDER_DFLT_PROPERTIES,
        PARSEC_PROVIDER_ECDSA_SIGN_IMPL,
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
        parsec_provider_teardown(provctx as *const OSSL_PROVIDER);
    }
}

#[test]
fn test_sign_dup() {
    use crate::keymgmt::{
        parsec_provider_kmgmt_free, parsec_provider_kmgmt_new, parsec_provider_kmgmt_set_params,
    };
    use crate::PARSEC_PROVIDER_KEY_NAME;
    use crate::{parsec_provider_provider_init, parsec_provider_teardown};
    use parsec_openssl2::openssl_bindings::OSSL_PARAM_UTF8_PTR;

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

    let keydata = unsafe { parsec_provider_kmgmt_new(provctx) };

    let my_key_name = "PARSEC_TEST_RSA_KEY".to_string();
    let mut params = [
        ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, my_key_name),
        ossl_param!(),
    ];

    let set_params_res = unsafe { parsec_provider_kmgmt_set_params(keydata, &mut params as _) };
    assert_eq!(set_params_res, OPENSSL_SUCCESS);

    let sig_ctx = unsafe { parsec_provider_signature_newctx(provctx, s.as_ptr() as _) };
    assert_ne!(sig_ctx, std::ptr::null_mut());

    unsafe { parsec_provider_signature_sign_init(sig_ctx, keydata, params.as_ptr()) };

    let duplicated_ptr = unsafe { parsec_provider_signature_dupctx(sig_ctx) };
    assert_ne!(duplicated_ptr, std::ptr::null_mut());
    assert_ne!(duplicated_ptr, sig_ctx);

    let arc_duplicated =
        unsafe { Arc::from_raw(duplicated_ptr as *const ParsecProviderSignatureContext) };
    {
        let binding = arc_duplicated.clone();
        let keyobj = binding.keyobj.lock().unwrap();

        let name = (*(keyobj)).clone().unwrap();
        assert_eq!(
            *(name.get_key_name()),
            Some("PARSEC_TEST_RSA_KEY".to_string())
        );
    }

    // We change back to using pointers instead of Arcs to use the provider's free
    let duplicated_ptr = Arc::into_raw(arc_duplicated) as VOID_PTR;
    unsafe {
        parsec_provider_signature_freectx(duplicated_ptr);
        parsec_provider_signature_freectx(sig_ctx);
        parsec_provider_kmgmt_free(keydata);
        parsec_provider_teardown(provctx as _);
    }
}
