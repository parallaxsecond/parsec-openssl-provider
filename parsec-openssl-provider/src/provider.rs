// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::keymgmt::PARSEC_PROVIDER_KEYMGMT;
use crate::signature::PARSEC_PROVIDER_SIGNATURE;

use parsec_openssl2::{
    locate_and_set_provider_status_param, locate_and_set_utf8_param, ossl_param, OPENSSL_ERROR,
    OPENSSL_SUCCESS, OSSL_PROVIDER,
};

use parsec_client::error::Result as ClientResult;
use parsec_client::BasicClient;
use std::sync::Arc;

use crate::openssl_bindings::{
    OSSL_ALGORITHM, OSSL_OP_KEYMGMT, OSSL_OP_SIGNATURE, OSSL_PARAM, OSSL_PARAM_INTEGER,
    OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_BUILDINFO, OSSL_PROV_PARAM_NAME, OSSL_PROV_PARAM_STATUS,
    OSSL_PROV_PARAM_VERSION,
};

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

// Parsec provider parameters
pub const PARSEC_PROVIDER_NAME: &[u8; 24] = b"Parsec OpenSSL Provider\0";
pub const PARSEC_PROVIDER_VERSION: &[u8; 6] = b"0.1.0\0";

// The types of parameters the provider supplies to the openssl library
const PARSEC_PROVIDER_PARAM_TYPES: [OSSL_PARAM; 5] = [
    // Provider name
    ossl_param!(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR),
    // Provider version
    ossl_param!(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR),
    // Build info
    ossl_param!(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR),
    // Provider Status
    ossl_param!(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER),
    ossl_param!(),
];

pub struct ParsecProviderContext {
    pub client: BasicClient,
}

impl ParsecProviderContext {
    pub fn new(client_name: String) -> ClientResult<Self> {
        let client = BasicClient::new(Some(client_name))?;
        Ok(ParsecProviderContext { client })
    }

    pub fn get_client(&self) -> &BasicClient {
        &self.client
    }
}

// Returns an array of OpenSSL parameter types that the
// provider supports
pub unsafe extern "C" fn parsec_provider_gettable_params(
    _provider: *const OSSL_PROVIDER,
) -> *const OSSL_PARAM {
    PARSEC_PROVIDER_PARAM_TYPES.as_ptr()
}

// Populates the provider's name, version and the status to parameter structure
pub unsafe extern "C" fn parsec_provider_get_params(
    _provctx: *const OSSL_PROVIDER,
    params: *mut OSSL_PARAM,
) -> ::std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_GET_PARAMS), || {
        // Find parameter of type OSSL_PROV_PARAM_NAME and populate it with PARSEC_PROVIDER_NAME
        locate_and_set_utf8_param(OSSL_PROV_PARAM_NAME, PARSEC_PROVIDER_NAME, params)?;

        // Find parameter of type OSSL_PROV_PARAM_VERSION and populate it with PARSEC_PROVIDER_VERSION
        locate_and_set_utf8_param(OSSL_PROV_PARAM_VERSION, PARSEC_PROVIDER_VERSION, params)?;

        // Find parameter of type OSSL_PROV_PARAM_STATUS and populate it with status 1
        locate_and_set_provider_status_param(params)?;

        Ok(OPENSSL_SUCCESS)
    });
    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
}

// Function pointer of type OSSL_FUNC_PROVIDER_GETTABLE_PARAMS
pub type ProviderGettableParamsPtr =
    unsafe extern "C" fn(*const OSSL_PROVIDER) -> *const OSSL_PARAM;

// Function pointer of type OSSL_FUNC_PROVIDER_GET_PARAMS
pub type ProviderGetParamsPtr = unsafe extern "C" fn(
    provctx: *const OSSL_PROVIDER,
    params: *mut OSSL_PARAM,
) -> ::std::os::raw::c_int;

// Function pointer of type OSSL_FUNC_PROVIDER_QUERY_OPERATION
pub type ProviderQueryPtr = unsafe extern "C" fn(
    prov: *mut OSSL_PROVIDER,
    operation_id: ::std::os::raw::c_int,
    no_cache: *mut ::std::os::raw::c_int,
) -> *const OSSL_ALGORITHM;

// Function pointer of type OSSL_FUNC_PROVIDER_TEARDOWN
pub type ProviderTeardownPtr = unsafe extern "C" fn(provctx: *const OSSL_PROVIDER);

#[repr(i32)]
#[derive(FromPrimitive, Clone, PartialEq, Eq)]
enum ParsecProviderOperationId {
    KeyMgmgt = OSSL_OP_KEYMGMT as i32,
    Signature = OSSL_OP_SIGNATURE as i32,
}

// The null provider implementation currently doesn't supply any algorithms to the core
pub unsafe extern "C" fn parsec_provider_query(
    _prov: *mut OSSL_PROVIDER,
    operation_id: ::std::os::raw::c_int,
    no_cache: *mut ::std::os::raw::c_int,
) -> *const OSSL_ALGORITHM {
    *no_cache = 0;

    let op_id = ParsecProviderOperationId::from_i32(operation_id);
    if let Some(id) = op_id {
        match id {
            ParsecProviderOperationId::KeyMgmgt => PARSEC_PROVIDER_KEYMGMT.as_ptr(),
            ParsecProviderOperationId::Signature => PARSEC_PROVIDER_SIGNATURE.as_ptr(),
        }
    } else {
        std::ptr::null_mut()
    }
}

// Teardowns the Provider context
pub unsafe extern "C" fn parsec_provider_teardown(provctx: *const OSSL_PROVIDER) {
    if provctx.is_null() {
        return;
    }
    // Makes sure the provider context gets dropped
    let provctx_ptr = provctx as *const ParsecProviderContext;
    let arc_provctx = Arc::from_raw(provctx_ptr);
    // A strong_count of 1 should be guaranteed by OPENSSL, as it doesn't make sense to be calling
    // free when you are still using provctx.
    assert_eq!(1, Arc::strong_count(&arc_provctx));
    // When provctx is dropped, the reference count is decremented and the memory is freed
}
