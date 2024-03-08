// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::openssl_binding::{
    OSSL_ALGORITHM, OSSL_DISPATCH, OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
    OSSL_PARAM, OSSL_PARAM_UTF8_PTR,
};
use crate::ParsecProviderContext;
use parsec_openssl2::types::VOID_PTR;
use parsec_openssl2::*;
use std::sync::{Arc, Mutex};

// Parameter names that Providers can define
const PARSEC_PROVIDER_RSA_NAME: &[u8; 4] = b"RSA\0";
const PARSEC_PROVIDER_DESCRIPTION_RSA: &[u8; 11] = b"Parsec RSA\0";
const PARSEC_PROVIDER_DFLT_PROPERTIES: &[u8; 16] = b"provider=parsec\0";
const PARSEC_PROVIDER_KEY_NAME: &[u8; 25] = b"parsec_provider_key_name\0";

struct ParsecProviderKeyObject {
    _provctx: Arc<ParsecProviderContext>,
    key_name: Mutex<Option<String>>,
}

fn kmgmt_keyobj_new(provctx: Arc<ParsecProviderContext>) -> Arc<ParsecProviderKeyObject> {
    Arc::new(ParsecProviderKeyObject {
        _provctx: provctx.clone(),
        key_name: None.into(),
    })
}

pub unsafe extern "C" fn parsec_provider_kmgmt_new(provctx: VOID_PTR) -> VOID_PTR {
    if provctx.is_null() {
        return std::ptr::null_mut();
    }
    let ctx = provctx as *const ParsecProviderContext;
    Arc::increment_strong_count(ctx);
    let context = Arc::from_raw(ctx);

    Arc::into_raw(kmgmt_keyobj_new(context)) as VOID_PTR
}

pub unsafe extern "C" fn parsec_provider_kmgmt_free(keydata: VOID_PTR) {
    if keydata.is_null() {
        return;
    }
    let keydata_ptr = keydata as *const ParsecProviderKeyObject;
    let arc_keydata = Arc::from_raw(keydata_ptr);
    // A strong_count of 1 should be guaranteed by OPENSSL, as it doesn't make sense to be calling
    // free when you are still using keydata.
    assert_eq!(1, Arc::strong_count(&arc_keydata));
    // When arc_keydata is dropped, the reference count is decremented and the memory is freed
}

pub unsafe extern "C" fn parsec_provider_kmgmt_settable_params(
    _provctx: VOID_PTR,
) -> *const OSSL_PARAM {
    static ONCE_INIT: std::sync::Once = std::sync::Once::new();
    static mut KEYMGMT_TABLE: [OSSL_PARAM; 1] = [parsec_openssl2::ossl_param!(); 1];

    ONCE_INIT.call_once(|| {
        KEYMGMT_TABLE = [ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR)];
    });

    KEYMGMT_TABLE.as_ptr()
}

pub type KeyMgmtNewPtr = unsafe extern "C" fn(VOID_PTR) -> VOID_PTR;
pub type KeyMgmtFreePtr = unsafe extern "C" fn(VOID_PTR);
pub type KeyMgmtSettableParamsPtr = unsafe extern "C" fn(VOID_PTR) -> *const OSSL_PARAM;

const OSSL_FUNC_KEYMGMT_NEW_PTR: KeyMgmtNewPtr = parsec_provider_kmgmt_new;
const OSSL_FUNC_KEYMGMT_FREE_PTR: KeyMgmtFreePtr = parsec_provider_kmgmt_free;
const OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS_PTR: KeyMgmtSettableParamsPtr =
    parsec_provider_kmgmt_settable_params;

const PARSEC_PROVIDER_RSA_KEYMGMT_IMPL: [OSSL_DISPATCH; 3] = [
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_NEW_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_FREE_PTR) },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
            OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS_PTR
        )
    },
];

pub const PARSEC_PROVIDER_KEYMGMT: [OSSL_ALGORITHM; 1] = [ossl_algorithm!(
    PARSEC_PROVIDER_RSA_NAME,
    PARSEC_PROVIDER_DFLT_PROPERTIES,
    PARSEC_PROVIDER_RSA_KEYMGMT_IMPL,
    PARSEC_PROVIDER_DESCRIPTION_RSA
)];
