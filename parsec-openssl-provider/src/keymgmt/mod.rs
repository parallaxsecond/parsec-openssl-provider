// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::openssl_bindings::{
    OSSL_ALGORITHM, OSSL_DISPATCH, OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_HAS,
    OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_NEW,
    OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_SET_PARAMS, OSSL_FUNC_KEYMGMT_VALIDATE,
    OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, OSSL_PARAM, OSSL_PARAM_UTF8_PTR,
};
use crate::{
    ParsecProviderContext, PARSEC_PROVIDER_DESCRIPTION_RSA, PARSEC_PROVIDER_DFLT_PROPERTIES,
    PARSEC_PROVIDER_KEY_NAME, PARSEC_PROVIDER_RSA_NAME,
};
use parsec_openssl2::types::VOID_PTR;
use parsec_openssl2::*;
use std::sync::{Arc, Mutex};

struct ParsecProviderKeyObject {
    provctx: Arc<ParsecProviderContext>,
    key_name: Mutex<Option<String>>,
}

fn kmgmt_keyobj_new(provctx: Arc<ParsecProviderContext>) -> Arc<ParsecProviderKeyObject> {
    Arc::new(ParsecProviderKeyObject {
        provctx: provctx.clone(),
        key_name: None.into(),
    })
}

/*
should create a provider side key object. The provider context provctx is passed and may be incorporated
in the key object, but that is not mandatory.
*/
pub unsafe extern "C" fn parsec_provider_kmgmt_new(provctx: VOID_PTR) -> VOID_PTR {
    if provctx.is_null() {
        return std::ptr::null_mut();
    }
    let ctx = provctx as *const ParsecProviderContext;
    Arc::increment_strong_count(ctx);
    let context = Arc::from_raw(ctx);

    Arc::into_raw(kmgmt_keyobj_new(context)) as VOID_PTR
}

// should free the passed keydata
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

/*
should return a constant array of descriptor OSSL_PARAM, for parameters that
OSSL_FUNC_keymgmt_set_params() can handle.
*/
pub unsafe extern "C" fn parsec_provider_kmgmt_settable_params(
    _provctx: VOID_PTR,
) -> *const OSSL_PARAM {
    static ONCE_INIT: std::sync::Once = std::sync::Once::new();
    static mut KEYMGMT_TABLE: [OSSL_PARAM; 2] = [ossl_param!(); 2];

    ONCE_INIT.call_once(|| {
        KEYMGMT_TABLE = [
            ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR),
            ossl_param!(),
        ];
    });

    KEYMGMT_TABLE.as_ptr()
}

// should update information data associated with the given keydata
pub unsafe extern "C" fn parsec_provider_kmgmt_set_params(
    keydata: VOID_PTR,
    params: *mut OSSL_PARAM,
) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_KEYMGMT_SET_PARAMS), || {
        if keydata.is_null() || params.is_null() {
            Err("Null pointer received as parameter".into())
        } else {
            let keyobj = keydata as *mut ParsecProviderKeyObject;
            Arc::increment_strong_count(keyobj);
            let arc_keyobj = Arc::from_raw(keyobj);

            let param: openssl_bindings::OSSL_PARAM =
                *openssl_returns_nonnull(openssl_bindings::OSSL_PARAM_locate(
                    params,
                    PARSEC_PROVIDER_KEY_NAME.as_ptr() as *const std::os::raw::c_char,
                ))?;

            let key_name: &mut [u8] =
                core::slice::from_raw_parts_mut(param.data as *mut u8, param.data_size);

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
For algorithms where some selection is not meaningful the function should just return 1 as the
selected subset is not really missing in the key.
*/
pub unsafe extern "C" fn parsec_provider_kmgmt_has(
    keydata: VOID_PTR,
    selection: std::os::raw::c_int,
) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_KEYMGMT_HAS), || {
        if keydata.is_null() {
            return Err("keydata pointer should not be NULL.".into());
        }

        if selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as std::os::raw::c_int != 0 {
            let keydata_ptr = keydata as *const ParsecProviderKeyObject;
            Arc::increment_strong_count(keydata_ptr);
            let arc_keydata = Arc::from_raw(keydata_ptr);
            let key_name = arc_keydata.key_name.lock().unwrap();
            if key_name.is_some() {
                Ok(OPENSSL_SUCCESS)
            } else {
                Err("key name has not been set.".into())
            }
        } else {
            Ok(OPENSSL_SUCCESS)
        }
    });

    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
}

pub unsafe extern "C" fn parsec_provider_kmgmt_import(
    key_data: VOID_PTR,
    selection: std::os::raw::c_int,
    params: *mut OSSL_PARAM,
) -> std::os::raw::c_int {
    //TODO: Query the parsec service and get a list of keys, check if the requested import is for a known key and then
    // set the parameter
    if selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as std::os::raw::c_int != 0 {
        return parsec_provider_kmgmt_set_params(key_data, params);
    }

    OPENSSL_SUCCESS
}

/*
should return an array of descriptor OSSL_PARAM for data indicated by selection, for parameters that
OSSL_FUNC_keymgmt_import() can handle
*/
pub unsafe extern "C" fn parsec_provider_kmgmt_import_types(
    selection: std::os::raw::c_int,
) -> *const OSSL_PARAM {
    if selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as std::os::raw::c_int != 0 {
        static ONCE_INIT: std::sync::Once = std::sync::Once::new();
        static mut IMPORT_TYPES_TABLE: [OSSL_PARAM; 2] = [ossl_param!(); 2];

        ONCE_INIT.call_once(|| {
            IMPORT_TYPES_TABLE = [
                ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR),
                ossl_param!(),
            ];
        });

        IMPORT_TYPES_TABLE.as_ptr()
    } else {
        std::ptr::null_mut()
    }
}

// Should check if the keydata contains valid data subsets indicated by selection.
pub unsafe extern "C" fn parsec_provider_kmgmt_validate(
    keydata: VOID_PTR,
    selection: std::os::raw::c_int,
    _checktype: std::os::raw::c_int,
) -> std::os::raw::c_int {
    if keydata.is_null() {
        return OPENSSL_ERROR;
    }

    if selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as std::os::raw::c_int != 0 {
        let keydata_ptr = keydata as *const ParsecProviderKeyObject;
        Arc::increment_strong_count(keydata_ptr);
        let arc_keydata = Arc::from_raw(keydata_ptr);
        let key_name = arc_keydata.key_name.lock().unwrap();
        let result =
            super::r#catch(
                Some(|| super::Error::PROVIDER_KEYMGMT_VALIDATE),
                || match &*key_name {
                    Some(name) => {
                        let keys = arc_keydata
                            .provctx
                            .get_client()
                            .list_keys()
                            .map_err(|_| "Failed to list Parsec Provider's Keys".to_string())?;

                        if keys.iter().any(|kinfo| kinfo.name == name.as_str()) {
                            Ok(OPENSSL_SUCCESS)
                        } else {
                            Err("Specified Key not found in the Parsec Provider".into())
                        }
                    }
                    None => Err("keydata to validate failed: Key name not specified".into()),
                },
            );

        match result {
            Ok(result) => result,
            Err(()) => OPENSSL_ERROR,
        }
    } else {
        OPENSSL_SUCCESS
    }
}

pub type KeyMgmtNewPtr = unsafe extern "C" fn(VOID_PTR) -> VOID_PTR;
pub type KeyMgmtFreePtr = unsafe extern "C" fn(VOID_PTR);
pub type KeyMgmtHasPtr = unsafe extern "C" fn(VOID_PTR, std::os::raw::c_int) -> std::os::raw::c_int;
pub type KeyMgmtImportPtr =
    unsafe extern "C" fn(VOID_PTR, std::os::raw::c_int, *mut OSSL_PARAM) -> std::os::raw::c_int;
pub type KeyMgmtImportTypesPtr = unsafe extern "C" fn(std::os::raw::c_int) -> *const OSSL_PARAM;
pub type KeyMgmtSetParamsPtr =
    unsafe extern "C" fn(VOID_PTR, *mut OSSL_PARAM) -> std::os::raw::c_int;
pub type KeyMgmtSettableParamsPtr = unsafe extern "C" fn(VOID_PTR) -> *const OSSL_PARAM;
pub type KeyMgmtValidatePtr =
    unsafe extern "C" fn(VOID_PTR, std::os::raw::c_int, std::os::raw::c_int) -> std::os::raw::c_int;

const OSSL_FUNC_KEYMGMT_NEW_PTR: KeyMgmtNewPtr = parsec_provider_kmgmt_new;
const OSSL_FUNC_KEYMGMT_FREE_PTR: KeyMgmtFreePtr = parsec_provider_kmgmt_free;
const OSSL_FUNC_KEYMGMT_HAS_PTR: KeyMgmtHasPtr = parsec_provider_kmgmt_has;
const OSSL_FUNC_KEYMGMT_IMPORT_PTR: KeyMgmtImportPtr = parsec_provider_kmgmt_import;
const OSSL_FUNC_KEYMGMT_IMPORT_TYPES_PTR: KeyMgmtImportTypesPtr =
    parsec_provider_kmgmt_import_types;
const OSSL_FUNC_KEYMGMT_SET_PARAMS_PTR: KeyMgmtSetParamsPtr = parsec_provider_kmgmt_set_params;
const OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS_PTR: KeyMgmtSettableParamsPtr =
    parsec_provider_kmgmt_settable_params;
const OSSL_FUNC_KEYMGMT_VALIDATE_PTR: KeyMgmtValidatePtr = parsec_provider_kmgmt_validate;

const PARSEC_PROVIDER_RSA_KEYMGMT_IMPL: [OSSL_DISPATCH; 9] = [
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_NEW_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_FREE_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_HAS_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_PTR) },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
            OSSL_FUNC_KEYMGMT_IMPORT_TYPES_PTR
        )
    },
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
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_VALIDATE, OSSL_FUNC_KEYMGMT_VALIDATE_PTR) },
    ossl_dispatch!(),
];

pub const PARSEC_PROVIDER_KEYMGMT: [OSSL_ALGORITHM; 2] = [
    ossl_algorithm!(
        PARSEC_PROVIDER_RSA_NAME,
        PARSEC_PROVIDER_DFLT_PROPERTIES,
        PARSEC_PROVIDER_RSA_KEYMGMT_IMPL,
        PARSEC_PROVIDER_DESCRIPTION_RSA
    ),
    ossl_algorithm!(),
];

#[test]
fn test_kmgmt_has() {
    use crate::openssl_bindings::OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    use crate::parsec_provider_provider_init;

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

    // Test parsec_provider_kmgmt_has when keyobj is null. Selection should not matter in this case
    let selec_w_null = unsafe {
        parsec_provider_kmgmt_has(
            std::ptr::null_mut(),
            OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32,
        )
    };
    assert_eq!(selec_w_null, OPENSSL_ERROR);

    let keyobj = unsafe { parsec_provider_kmgmt_new(provctx) };
    /* Test parsec_provider_kmgmt_has when the name parameter in keyobj has not been set and the correct selection is
    used */
    let selec_no_init =
        unsafe { parsec_provider_kmgmt_has(keyobj, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32) };
    assert_eq!(selec_no_init, OPENSSL_ERROR);

    /* Test parsec_provider_kmgmt_has when the name parameter in keyobj has not been set but a superfluous selection
    is used */
    let no_selec_no_init =
        unsafe { parsec_provider_kmgmt_has(keyobj, OSSL_KEYMGMT_SELECT_PRIVATE_KEY as i32) };
    assert_eq!(no_selec_no_init, OPENSSL_SUCCESS);

    // Set the key data with the correct name
    let my_key_name = "PARSEC_TEST_KEYNAME".to_string();
    let mut params = [
        ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, my_key_name),
        ossl_param!(),
    ];

    let set_params_res = unsafe { parsec_provider_kmgmt_set_params(keyobj, &mut params as _) };
    assert_eq!(set_params_res, OPENSSL_SUCCESS);

    // Check parsec_provider_kmgmt_has confirms that keyobj now has the correct data
    let selec_init =
        unsafe { parsec_provider_kmgmt_has(keyobj, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32) };
    assert_eq!(selec_init, OPENSSL_SUCCESS);

    unsafe {
        parsec_provider_kmgmt_free(keyobj);
    }
}

#[test]
fn test_kmgmt_validate() {
    use crate::parsec_provider_provider_init;

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

    let keyctx = unsafe { parsec_provider_kmgmt_new(provctx) };

    // Check that validate fails with "bad" data
    let bad_key_name = "BAD-NAME".to_string();
    let mut bad_params = [
        ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, bad_key_name),
        ossl_param!(),
    ];

    let set_params_res = unsafe { parsec_provider_kmgmt_set_params(keyctx, &mut bad_params as _) };
    assert_eq!(set_params_res, OPENSSL_SUCCESS);

    let result = unsafe {
        parsec_provider_kmgmt_validate(
            keyctx as VOID_PTR,
            OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32,
            0,
        )
    };
    assert_eq!(result, OPENSSL_ERROR);

    // Check that validate succeeds with "good" data
    let my_key_name = "PARSEC_TEST_KEYNAME".to_string();
    let mut params = [
        ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, my_key_name),
        ossl_param!(),
    ];

    let set_params_res = unsafe { parsec_provider_kmgmt_set_params(keyctx, &mut params as _) };
    assert_eq!(set_params_res, OPENSSL_SUCCESS);

    let result = unsafe {
        parsec_provider_kmgmt_validate(
            keyctx as VOID_PTR,
            OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32,
            0,
        )
    };
    assert_eq!(result, OPENSSL_SUCCESS);

    unsafe {
        parsec_provider_kmgmt_free(keyctx);
    }
}
