// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::openssl_bindings::{
    OSSL_ALGORITHM, OSSL_DISPATCH, OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_NEWCTX,
};
use crate::{
    PARSEC_PROVIDER_DESCRIPTION_ECDSA, PARSEC_PROVIDER_DESCRIPTION_RSA,
    PARSEC_PROVIDER_DFLT_PROPERTIES, PARSEC_PROVIDER_ECDSA_NAME, PARSEC_PROVIDER_RSA_NAME,
};
use parsec_openssl2::types::VOID_PTR;
use parsec_openssl2::*;

use std::sync::Arc;

struct ParsecProviderSignatureContext {
    /* The key object is set in the signature context by calling OSSL_FUNC_signature_sign_init().
    Before calling OSSL_FUNC_signature_sign_init(), the key object itself should have been set up
    and initialized via keymgmt function calls.
    */
}

impl ParsecProviderSignatureContext {
    pub fn new() -> Self {
        ParsecProviderSignatureContext {}
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

pub type SignatureNewCtxPtr =
    unsafe extern "C" fn(VOID_PTR, *const std::os::raw::c_char) -> VOID_PTR;
pub type SignatureFreeCtxPtr = unsafe extern "C" fn(VOID_PTR);

const OSSL_FUNC_SIGNATURE_NEWCTX_PTR: SignatureNewCtxPtr = parsec_provider_signature_newctx;
const OSSL_FUNC_SIGNATURE_FREECTX_PTR: SignatureFreeCtxPtr = parsec_provider_signature_freectx;

const PARSEC_PROVIDER_ECDSA_SIGN_IMPL: [OSSL_DISPATCH; 1] = [ossl_dispatch!()];
const PARSEC_PROVIDER_RSA_SIGN_IMPL: [OSSL_DISPATCH; 3] = [
    unsafe { ossl_dispatch!(OSSL_FUNC_SIGNATURE_NEWCTX, OSSL_FUNC_SIGNATURE_NEWCTX_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_SIGNATURE_FREECTX, OSSL_FUNC_SIGNATURE_FREECTX_PTR) },
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
