// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::openssl_binding::{
    OSSL_ALGORITHM, OSSL_DISPATCH, OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_HAS,
    OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_SET_PARAMS, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, OSSL_PARAM,
    OSSL_PARAM_UTF8_PTR,
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

pub unsafe extern "C" fn parsec_provider_kmgmt_set_params(
    keydata: VOID_PTR,
    params: *mut OSSL_PARAM,
) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_GET_PARAMS), || {
        if keydata.is_null() || params.is_null() {
            Err("Null pointer received as parameter".into())
        } else {
            let keyobj = keydata as *mut ParsecProviderKeyObject;
            Arc::increment_strong_count(keyobj);
            let arc_keyobj = Arc::from_raw(keyobj);

            let param: openssl_binding::OSSL_PARAM =
                *openssl_returns_nonnull(openssl_binding::OSSL_PARAM_locate(
                    params,
                    PARSEC_PROVIDER_KEY_NAME.as_ptr() as *const std::os::raw::c_char,
                ))?;

            let key_name: &mut [u8] =
                unsafe { core::slice::from_raw_parts_mut(param.data as *mut u8, param.data_size) };

            let mut keyobj_key_name = arc_keyobj.key_name.lock().unwrap();
            *keyobj_key_name = Some(std::str::from_utf8(key_name)?.to_string());

            Ok(OPENSSL_SUCCESS)
        }
    });

    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
}

/*
should return 1 if all the selected data subsets are contained in the given keydata or 0 otherwise.
*/
pub unsafe extern "C" fn parsec_provider_kmgmt_has(
    keydata: VOID_PTR,
    selection: std::os::raw::c_int,
) -> std::os::raw::c_int {
    if keydata.is_null() {
        return 1;
    }

    if selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as std::os::raw::c_int != 0 {
        let keydata_ptr = keydata as *const ParsecProviderKeyObject;
        Arc::increment_strong_count(keydata_ptr);
        let arc_keydata = Arc::from_raw(keydata_ptr);
        let key_name = arc_keydata.key_name.lock().unwrap();
        if key_name.is_some() {
            0
        } else {
            1
        }
    } else {
        1
    }
}

pub unsafe extern "C" fn parsec_provider_kmgmt_import(
    key_data: VOID_PTR,
    selection: std::os::raw::c_int,
    params: *mut OSSL_PARAM,
) -> std::os::raw::c_int {
    if selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as std::os::raw::c_int != 0 {
        return parsec_provider_kmgmt_set_params(key_data, params);
    }

    1
}

pub type KeyMgmtNewPtr = unsafe extern "C" fn(VOID_PTR) -> VOID_PTR;
pub type KeyMgmtFreePtr = unsafe extern "C" fn(VOID_PTR);
pub type KeyMgmtHasPtr = unsafe extern "C" fn(VOID_PTR, std::os::raw::c_int) -> std::os::raw::c_int;
pub type KeyMgmtImportPtr =
    unsafe extern "C" fn(VOID_PTR, std::os::raw::c_int, *mut OSSL_PARAM) -> std::os::raw::c_int;
pub type KeyMgmtSetParamsPtr =
    unsafe extern "C" fn(VOID_PTR, *mut OSSL_PARAM) -> std::os::raw::c_int;
pub type KeyMgmtSettableParamsPtr = unsafe extern "C" fn(VOID_PTR) -> *const OSSL_PARAM;

const OSSL_FUNC_KEYMGMT_NEW_PTR: KeyMgmtNewPtr = parsec_provider_kmgmt_new;
const OSSL_FUNC_KEYMGMT_FREE_PTR: KeyMgmtFreePtr = parsec_provider_kmgmt_free;
const OSSL_FUNC_KEYMGMT_HAS_PTR: KeyMgmtHasPtr = parsec_provider_kmgmt_has;
const OSSL_FUNC_KEYMGMT_IMPORT_PTR: KeyMgmtImportPtr = parsec_provider_kmgmt_import;
const OSSL_FUNC_KEYMGMT_SET_PARAMS_PTR: KeyMgmtSetParamsPtr = parsec_provider_kmgmt_set_params;
const OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS_PTR: KeyMgmtSettableParamsPtr =
    parsec_provider_kmgmt_settable_params;

const PARSEC_PROVIDER_RSA_KEYMGMT_IMPL: [OSSL_DISPATCH; 6] = [
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_NEW_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_FREE_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_HAS_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_PTR) },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_KEYMGMT_SET_PARAMS,
            OSSL_FUNC_KEYMGMT_SET_PARAMS_PTR
        )
    },
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
