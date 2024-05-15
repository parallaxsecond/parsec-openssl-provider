// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::openssl_bindings::*;
use crate::{
    ParsecProviderContext, PARSEC_PROVIDER_DESCRIPTION_ECDSA, PARSEC_PROVIDER_DESCRIPTION_RSA,
    PARSEC_PROVIDER_DFLT_PROPERTIES, PARSEC_PROVIDER_ECDSA_NAME, PARSEC_PROVIDER_KEY_NAME,
    PARSEC_PROVIDER_RSA_NAME,
};
use parsec_openssl2::types::VOID_PTR;
use parsec_openssl2::*;
use picky_asn1;
use picky_asn1_x509::RsaPublicKey;
use std::slice;
use std::sync::{Arc, RwLock};

pub struct ParsecProviderKeyObject {
    provctx: Arc<ParsecProviderContext>,
    key_name: Option<String>,
    rsa_key: Option<RsaPublicKey>,
}

impl Clone for ParsecProviderKeyObject {
    fn clone(&self) -> Self {
        ParsecProviderKeyObject {
            provctx: self.provctx.clone(),
            key_name: self.key_name.clone(),
            rsa_key: self.rsa_key.clone(),
        }
    }
}

impl ParsecProviderKeyObject {
    pub fn new(provctx: Arc<ParsecProviderContext>) -> Self {
        ParsecProviderKeyObject {
            provctx: provctx.clone(),
            key_name: None,
            rsa_key: None,
        }
    }

    pub fn get_provctx(&self) -> Arc<ParsecProviderContext> {
        self.provctx.clone()
    }

    pub fn get_key_name(&self) -> &Option<String> {
        &self.key_name
    }

    pub fn get_rsa_key(&self) -> &Option<RsaPublicKey> {
        &self.rsa_key
    }
}

/*
should create a provider side key object. The provider context provctx is passed and may be incorporated
in the key object, but that is not mandatory.
*/
pub unsafe extern "C" fn parsec_provider_kmgmt_new(provctx: VOID_PTR) -> VOID_PTR {
    if provctx.is_null() {
        return std::ptr::null_mut();
    }

    Arc::increment_strong_count(provctx as *const ParsecProviderContext);
    let prov_ctx = Arc::from_raw(provctx as *const ParsecProviderContext);

    Arc::into_raw(Arc::new(RwLock::new(ParsecProviderKeyObject::new(
        prov_ctx,
    )))) as VOID_PTR
}

// should free the passed keydata
pub unsafe extern "C" fn parsec_provider_kmgmt_free(keydata: VOID_PTR) {
    if keydata.is_null() {
        return;
    }
    let key_data = Arc::from_raw(keydata as *const RwLock<ParsecProviderKeyObject>);
    // A strong_count of 1 should be guaranteed by OPENSSL, as it doesn't make sense to be calling
    // free when you are still using keydata.
    assert_eq!(1, Arc::strong_count(&key_data));
    // When key_data is dropped, the reference count is decremented and the memory is freed
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

/*
should return a constant array of descriptor OSSL_PARAM, for parameters that OSSL_FUNC_keymgmt_get_params() can handle
 */
pub unsafe extern "C" fn parsec_provider_kmgmt_gettable_params(
    _provctx: VOID_PTR,
) -> *const OSSL_PARAM {
    static ONCE_INIT: std::sync::Once = std::sync::Once::new();
    static mut KEYMGMT_GETTABLE_TABLE: [OSSL_PARAM; 4] = [ossl_param!(); 4];

    ONCE_INIT.call_once(|| {
        KEYMGMT_GETTABLE_TABLE = [
            ossl_param!(OSSL_PKEY_PARAM_BITS, OSSL_PARAM_INTEGER),
            ossl_param!(OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PARAM_INTEGER),
            ossl_param!(OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PARAM_INTEGER),
            ossl_param!(),
        ];
    });
    KEYMGMT_GETTABLE_TABLE.as_ptr()
}

/*
should extract information data associated with the given keydata
 */
pub unsafe extern "C" fn parsec_provider_kmgmt_get_params(
    keydata: VOID_PTR,
    params: *mut OSSL_PARAM,
) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_KEYMGMT_GET_PARAMS), || {
        if keydata.is_null() || params.is_null() {
            Err("Null pointer received as parameter".into())
        } else {
            Arc::increment_strong_count(keydata as *const RwLock<ParsecProviderKeyObject>);
            let key_data = Arc::from_raw(keydata as *const RwLock<ParsecProviderKeyObject>);
            let reader_key_data = key_data.read().unwrap();

            if let Some(public_key) = reader_key_data.get_rsa_key() {
                let modulus = public_key.modulus.as_unsigned_bytes_be();

                locate_and_set_int_param(OSSL_PKEY_PARAM_BITS, modulus.len() * 8, params)?;
                locate_and_set_int_param(OSSL_PKEY_PARAM_SECURITY_BITS, 112, params)?;
                locate_and_set_int_param(OSSL_PKEY_PARAM_MAX_SIZE, modulus.len(), params)?;
            }

            Ok(OPENSSL_SUCCESS)
        }
    });

    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
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
            let param: openssl_bindings::OSSL_PARAM =
                *openssl_returns_nonnull(openssl_bindings::OSSL_PARAM_locate(
                    params,
                    PARSEC_PROVIDER_KEY_NAME.as_ptr() as *const std::os::raw::c_char,
                ))?;

            let key_name: &mut [u8] =
                core::slice::from_raw_parts_mut(param.data as *mut u8, param.data_size);

            Arc::increment_strong_count(keydata as *const RwLock<ParsecProviderKeyObject>);
            let key_data = Arc::from_raw(keydata as *const RwLock<ParsecProviderKeyObject>);

            let mut writer_key_data = key_data.write().unwrap();
            writer_key_data.key_name = Some(std::str::from_utf8(key_name)?.to_string());

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
            Arc::increment_strong_count(keydata as *const RwLock<ParsecProviderKeyObject>);
            let key_data = Arc::from_raw(keydata as *const RwLock<ParsecProviderKeyObject>);
            let reader_key_data = key_data.read().unwrap();
            if reader_key_data.get_key_name().is_some() {
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

/*
Reads the modulus and exponent components of the RSA key from the parameters and
returns a public key of type RsaPublicKey
*/
unsafe fn parsec_rsa_set_public_params(params: *mut OSSL_PARAM) -> Result<RsaPublicKey, String> {
    // Read the modulus
    let mod_param: openssl_bindings::OSSL_PARAM =
        *openssl_returns_nonnull(openssl_bindings::OSSL_PARAM_locate(
            params,
            OSSL_PKEY_PARAM_RSA_N.as_ptr() as *const std::os::raw::c_char,
        ))
        .map_err(|_| "OSSL_PKEY_PARAM_RSA_N not found".to_string())?;

    let mut modulus =
        slice::from_raw_parts(mod_param.data as *const u8, mod_param.data_size).to_vec();
    //ToDo: endianess
    modulus.reverse();
    let modulus = picky_asn1::wrapper::IntegerAsn1::from_bytes_be_unsigned(modulus);

    // Read the exponent
    let exp_param: openssl_bindings::OSSL_PARAM =
        *openssl_returns_nonnull(openssl_bindings::OSSL_PARAM_locate(
            params,
            OSSL_PKEY_PARAM_RSA_E.as_ptr() as *const std::os::raw::c_char,
        ))
        .map_err(|_| "OSSL_PKEY_PARAM_RSA_E not found".to_string())?;

    let mut exp = slice::from_raw_parts(exp_param.data as *const u8, exp_param.data_size).to_vec();
    //ToDo: endianess
    exp.reverse();
    let exp = picky_asn1::wrapper::IntegerAsn1::from_bytes_be_unsigned(exp);

    // Create a public key and return
    let public_key = RsaPublicKey {
        modulus: modulus,
        public_exponent: exp,
    };
    Ok(public_key)
}

/*
should import data indicated by selection into keydata with values taken from the OSSL_PARAM array params
*/
pub unsafe extern "C" fn parsec_provider_kmgmt_import(
    keydata: VOID_PTR,
    selection: std::os::raw::c_int,
    params: *mut OSSL_PARAM,
) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_KEYMGMT_IMPORT), || {
        Arc::increment_strong_count(keydata as *const RwLock<ParsecProviderKeyObject>);
        let key_data = Arc::from_raw(keydata as *const RwLock<ParsecProviderKeyObject>);
        let mut writer_key_data = key_data.write().unwrap();

        let provider_key_name = openssl_returns_nonnull(openssl_bindings::OSSL_PARAM_locate(
            params,
            PARSEC_PROVIDER_KEY_NAME.as_ptr() as *const std::os::raw::c_char,
        ));

        if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as std::os::raw::c_int != 0)
            && provider_key_name.is_ok()
        {
            let name_param = *provider_key_name.unwrap();
            let key_name = std::str::from_utf8_unchecked(core::slice::from_raw_parts(
                name_param.data as *mut u8,
                name_param.data_size,
            ));

            let keys = writer_key_data
                .provctx
                .get_client()
                .list_keys()
                .map_err(|_| "Failed to list Parsec Provider's Keys".to_string())?;

            if keys.iter().any(|kinfo| kinfo.name == key_name) {
                let key_name: &mut [u8] = core::slice::from_raw_parts_mut(
                    name_param.data as *mut u8,
                    name_param.data_size,
                );
                let key_name = std::str::from_utf8(key_name)?;
                writer_key_data.key_name = Some(key_name.to_string());

                let rsa_bytes = writer_key_data
                    .provctx
                    .get_client()
                    .psa_export_public_key(key_name)
                    .map_err(|e| format!("Parsec Client failed to sign: {:?}", e))?;
                let public_key: RsaPublicKey = picky_asn1_der::from_bytes(&rsa_bytes)
                    .map_err(|_| "Failed to parse RsaPublicKey data".to_string())?;
                writer_key_data.rsa_key = Some(public_key);
            } else {
                return Err("Invalid key name".to_string().into());
            }
            return Ok(OPENSSL_SUCCESS);
        }

        if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY as std::os::raw::c_int != 0 {
            let rsa_key = parsec_rsa_set_public_params(params)
                .map_err(|_| "Failed to set RSA public keys".to_string())?;
            writer_key_data.rsa_key = Some(rsa_key);
        }
        Ok(OPENSSL_SUCCESS)
    });
    match result {
        Ok(_) => OPENSSL_SUCCESS,
        Err(()) => OPENSSL_ERROR,
    }
}

/*
should return an array of descriptor OSSL_PARAM for data indicated by selection, for parameters that
OSSL_FUNC_keymgmt_import() can handle
*/
pub unsafe extern "C" fn parsec_provider_kmgmt_import_types(
    selection: std::os::raw::c_int,
) -> *const OSSL_PARAM {
    if selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS as std::os::raw::c_int != 0 {
        static ONCE_INIT: std::sync::Once = std::sync::Once::new();
        static mut IMPORT_TYPES_TABLE: [OSSL_PARAM; 4] = [ossl_param!(); 4];

        ONCE_INIT.call_once(|| {
            IMPORT_TYPES_TABLE = [
                ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR),
                ossl_param!(OSSL_PKEY_PARAM_RSA_N, OSSL_PARAM_UNSIGNED_INTEGER),
                ossl_param!(OSSL_PKEY_PARAM_RSA_E, OSSL_PARAM_UNSIGNED_INTEGER),
                ossl_param!(),
            ];
        });

        IMPORT_TYPES_TABLE.as_ptr()
    } else {
        std::ptr::null_mut()
    }
}

/*
should check if the data subset indicated by selection in keydata1 and keydata2 match.
It is assumed that the caller has ensured that keydata1 and keydata2 are both owned by the implementation of this function.
*/
pub unsafe extern "C" fn parsec_provider_kmgmt_match(
    keydata1: VOID_PTR,
    keydata2: VOID_PTR,
    selection: std::os::raw::c_int,
) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_KEYMGMT_MATCH), || {
        if keydata1 == keydata2 {
            return Ok(OPENSSL_SUCCESS);
        }
        if keydata1.is_null() ^ keydata2.is_null() {
            return Err("One of the keydatas to compare is null".into());
        }

        if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY as std::os::raw::c_int != 0 {
            Arc::increment_strong_count(keydata1 as *const RwLock<ParsecProviderKeyObject>);
            Arc::increment_strong_count(keydata2 as *const RwLock<ParsecProviderKeyObject>);

            let key_data1 = Arc::from_raw(keydata1 as *const RwLock<ParsecProviderKeyObject>);
            let key_data2 = Arc::from_raw(keydata2 as *const RwLock<ParsecProviderKeyObject>);

            let reader_key_data1 = key_data1.read().unwrap();
            let reader_key_data2 = key_data2.read().unwrap();

            if reader_key_data1.get_rsa_key() == reader_key_data2.get_rsa_key() {
                Ok(OPENSSL_SUCCESS)
            } else {
                Err("Public parts of the keys do not match".into())
            }
        } else {
            Err("Keys do not match".into())
        }
    });

    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
}

/*
should duplicate data subsets indicated by selection or the whole key data keydata_from and create a new provider side
key object with the data.
*/
pub unsafe extern "C" fn parsec_provider_keymgmt_dup(
    keydata_from: VOID_PTR,
    selection: std::os::raw::c_int,
) -> VOID_PTR {
    if selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as std::os::raw::c_int != 0 {
        Arc::increment_strong_count(keydata_from as *const RwLock<ParsecProviderKeyObject>);
        let key_data_from = Arc::from_raw(keydata_from as *const RwLock<ParsecProviderKeyObject>);

        let reader_key_data_from = key_data_from.read().unwrap();
        let duplicate: RwLock<ParsecProviderKeyObject> = RwLock::new(reader_key_data_from.clone());
        Arc::into_raw(Arc::new(duplicate)) as VOID_PTR
    } else {
        std::ptr::null_mut()
    }
}

pub unsafe extern "C" fn parsec_provider_kmgmt_query_operation_name(
    _operation_id: std::os::raw::c_int,
) -> *const std::os::raw::c_char {
    return PARSEC_PROVIDER_RSA_NAME.as_ptr() as *const std::os::raw::c_char;
}

const OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME_PTR: KeyMgmtQueryOperationNamePtr =
    parsec_provider_kmgmt_query_operation_name;
pub type KeyMgmtQueryOperationNamePtr =
    unsafe extern "C" fn(std::os::raw::c_int) -> *const std::os::raw::c_char;
pub type KeyMgmtDupPtr = unsafe extern "C" fn(VOID_PTR, std::os::raw::c_int) -> VOID_PTR;
pub type KeyMgmtNewPtr = unsafe extern "C" fn(VOID_PTR) -> VOID_PTR;
pub type KeyMgmtFreePtr = unsafe extern "C" fn(VOID_PTR);
pub type KeyMgmtHasPtr = unsafe extern "C" fn(VOID_PTR, std::os::raw::c_int) -> std::os::raw::c_int;
pub type KeyMgmtImportPtr =
    unsafe extern "C" fn(VOID_PTR, std::os::raw::c_int, *mut OSSL_PARAM) -> std::os::raw::c_int;
pub type KeyMgmtImportTypesPtr = unsafe extern "C" fn(std::os::raw::c_int) -> *const OSSL_PARAM;
pub type KeyMgmtSetParamsPtr =
    unsafe extern "C" fn(VOID_PTR, *mut OSSL_PARAM) -> std::os::raw::c_int;
pub type KeyMgmtGetParamsPtr =
    unsafe extern "C" fn(VOID_PTR, *mut OSSL_PARAM) -> std::os::raw::c_int;
pub type KeyMgmtSettableParamsPtr = unsafe extern "C" fn(VOID_PTR) -> *const OSSL_PARAM;
pub type KeyMgmtGettableParamsPtr = unsafe extern "C" fn(VOID_PTR) -> *const OSSL_PARAM;

pub type KeyMgmtMatchPtr =
    unsafe extern "C" fn(VOID_PTR, VOID_PTR, std::os::raw::c_int) -> std::os::raw::c_int;

const OSSL_FUNC_KEYMGMT_DUP_PTR: KeyMgmtDupPtr = parsec_provider_keymgmt_dup;
const OSSL_FUNC_KEYMGMT_NEW_PTR: KeyMgmtNewPtr = parsec_provider_kmgmt_new;
const OSSL_FUNC_KEYMGMT_FREE_PTR: KeyMgmtFreePtr = parsec_provider_kmgmt_free;
const OSSL_FUNC_KEYMGMT_HAS_PTR: KeyMgmtHasPtr = parsec_provider_kmgmt_has;
const OSSL_FUNC_KEYMGMT_IMPORT_PTR: KeyMgmtImportPtr = parsec_provider_kmgmt_import;
const OSSL_FUNC_KEYMGMT_IMPORT_TYPES_PTR: KeyMgmtImportTypesPtr =
    parsec_provider_kmgmt_import_types;
const OSSL_FUNC_KEYMGMT_SET_PARAMS_PTR: KeyMgmtSetParamsPtr = parsec_provider_kmgmt_set_params;
const OSSL_FUNC_KEYMGMT_GET_PARAMS_PTR: KeyMgmtGetParamsPtr = parsec_provider_kmgmt_get_params;
const OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS_PTR: KeyMgmtSettableParamsPtr =
    parsec_provider_kmgmt_settable_params;
const OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS_PTR: KeyMgmtGettableParamsPtr =
    parsec_provider_kmgmt_gettable_params;

const OSSL_FUNC_KEYMGMT_MATCH_PTR: KeyMgmtMatchPtr = parsec_provider_kmgmt_match;

const PARSEC_PROVIDER_KEYMGMT_IMPL: [OSSL_DISPATCH; 13] = [
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_DUP_PTR) },
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
            OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
            OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME_PTR
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
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_KEYMGMT_GET_PARAMS,
            OSSL_FUNC_KEYMGMT_GET_PARAMS_PTR
        )
    },
    unsafe {
        ossl_dispatch!(
            OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
            OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS_PTR
        )
    },
    unsafe { ossl_dispatch!(OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_MATCH_PTR) },
    ossl_dispatch!(),
];

pub const PARSEC_PROVIDER_KEYMGMT: [OSSL_ALGORITHM; 3] = [
    ossl_algorithm!(
        PARSEC_PROVIDER_ECDSA_NAME,
        PARSEC_PROVIDER_DFLT_PROPERTIES,
        PARSEC_PROVIDER_KEYMGMT_IMPL,
        PARSEC_PROVIDER_DESCRIPTION_ECDSA
    ),
    ossl_algorithm!(
        PARSEC_PROVIDER_RSA_NAME,
        PARSEC_PROVIDER_DFLT_PROPERTIES,
        PARSEC_PROVIDER_KEYMGMT_IMPL,
        PARSEC_PROVIDER_DESCRIPTION_RSA
    ),
    ossl_algorithm!(),
];

#[test]
fn test_kmgmt_has() {
    use crate::openssl_bindings::OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
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
    let my_key_name = "PARSEC_TEST_RSA_KEY".to_string();
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
        parsec_provider_teardown(provctx as *const OSSL_PROVIDER);
    }
}

#[test]
fn test_kmgmt_match() {
    use crate::openssl_bindings::OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
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

    let keyobj1 = std::ptr::null_mut();
    let keyobj2 = std::ptr::null_mut();

    // Check edge case 1: Both keyobj are NULL
    let result = unsafe {
        parsec_provider_kmgmt_match(
            keyobj1,
            keyobj2,
            OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32,
        )
    };
    assert_eq!(result, OPENSSL_SUCCESS);

    // Check edge case 2: One keyobj is NULL, the other is not
    let keyobj1 = unsafe { parsec_provider_kmgmt_new(provctx) };
    let result = unsafe {
        parsec_provider_kmgmt_match(
            keyobj1,
            keyobj2,
            OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32,
        )
    };
    assert_eq!(result, OPENSSL_ERROR);

    // Check the case in which both keyobj are empty
    let keyobj2 = unsafe { parsec_provider_kmgmt_new(provctx) };
    let result = unsafe {
        parsec_provider_kmgmt_match(
            keyobj1,
            keyobj2,
            OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32,
        )
    };
    assert_eq!(result, OPENSSL_SUCCESS);

    // Check the case in which one keyobj are empty, the other has a key_name set
    let key_name1 = "KEY-NAME1".to_string();
    let mut key1_params = [
        ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, key_name1),
        ossl_param!(),
    ];
    let set_params_res1 =
        unsafe { parsec_provider_kmgmt_set_params(keyobj1, &mut key1_params as _) };
    assert_eq!(set_params_res1, OPENSSL_SUCCESS);

    let result = unsafe {
        parsec_provider_kmgmt_match(
            keyobj1,
            keyobj2,
            OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32,
        )
    };
    assert_eq!(result, OPENSSL_ERROR);

    // Check the case in which both keyobj have a set key_name but these are different from each other
    let key_name2 = "KEY-NAME2".to_string();
    let mut key2_params = [
        ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, key_name2),
        ossl_param!(),
    ];
    let set_params_res2 =
        unsafe { parsec_provider_kmgmt_set_params(keyobj2, &mut key2_params as _) };
    assert_eq!(set_params_res2, OPENSSL_SUCCESS);

    let result = unsafe {
        parsec_provider_kmgmt_match(
            keyobj1,
            keyobj2,
            OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32,
        )
    };
    assert_eq!(result, OPENSSL_ERROR);

    /* Check the case in which a parameter other than OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS is used
    this should be ok, as the only match we care about right now is for
    OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS*/
    let result = unsafe {
        parsec_provider_kmgmt_match(keyobj1, keyobj2, OSSL_KEYMGMT_SELECT_PRIVATE_KEY as i32)
    };
    assert_eq!(result, OPENSSL_SUCCESS);

    /* Check the case in which both keyobj have the same name set and the relevant selection
    (OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) is used*/
    let key_name2 = "KEY-NAME1".to_string();
    let mut key2_params = [
        ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, key_name2),
        ossl_param!(),
    ];
    let set_params_res2 =
        unsafe { parsec_provider_kmgmt_set_params(keyobj2, &mut key2_params as _) };
    assert_eq!(set_params_res2, OPENSSL_SUCCESS);

    let result = unsafe {
        parsec_provider_kmgmt_match(
            keyobj1,
            keyobj2,
            OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32,
        )
    };
    assert_eq!(result, OPENSSL_SUCCESS);

    unsafe {
        parsec_provider_kmgmt_free(keyobj1);
        parsec_provider_kmgmt_free(keyobj2);
        parsec_provider_teardown(provctx as *const OSSL_PROVIDER);
    }
}

#[test]
fn test_kmgmt_import() {
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

    let keyctx = unsafe { parsec_provider_kmgmt_new(provctx) };

    // Check that import fails with "bad" data
    let bad_key_name = "BAD-NAME".to_string();
    let mut bad_params = [
        ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, bad_key_name),
        ossl_param!(),
    ];
    let bad_import_res = unsafe {
        parsec_provider_kmgmt_import(
            keyctx,
            OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32,
            &mut bad_params as _,
        )
    };
    assert_eq!(bad_import_res, OPENSSL_ERROR);

    // Check that import succeeds with "good" data
    let good_key_name = "PARSEC_TEST_RSA_KEY".to_string();
    let mut good_params = [
        ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, good_key_name),
        ossl_param!(),
    ];

    let good_import_res = unsafe {
        parsec_provider_kmgmt_import(
            keyctx,
            OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32,
            &mut good_params as _,
        )
    };
    assert_eq!(good_import_res, OPENSSL_SUCCESS);

    unsafe {
        parsec_provider_kmgmt_free(keyctx);
        parsec_provider_teardown(provctx as *const OSSL_PROVIDER);
    }
}

#[test]
fn test_kmgmt_dup() {
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

    let keyobj = unsafe { parsec_provider_kmgmt_new(provctx) };

    let my_key_name = "PARSEC_TEST_RSA_KEY".to_string();
    let mut params = [
        ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, my_key_name),
        ossl_param!(),
    ];
    let set_params_res = unsafe { parsec_provider_kmgmt_set_params(keyobj, &mut params as _) };
    assert_eq!(set_params_res, OPENSSL_SUCCESS);

    let duplicated =
        unsafe { parsec_provider_keymgmt_dup(keyobj, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as i32) };

    unsafe {
        Arc::increment_strong_count(duplicated as *const RwLock<ParsecProviderKeyObject>);
        let arc_duplicated = Arc::from_raw(duplicated as *const RwLock<ParsecProviderKeyObject>);
        let reader_dup = arc_duplicated.read().unwrap();

        assert_eq!(reader_dup.key_name, Some(my_key_name))
    }

    unsafe {
        parsec_provider_kmgmt_free(keyobj);
        parsec_provider_kmgmt_free(duplicated);
        parsec_provider_teardown(provctx as _);
    }
}
