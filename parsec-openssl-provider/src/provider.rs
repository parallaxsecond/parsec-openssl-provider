// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use parsec_openssl2::{
    locate_and_set_provider_status_param, locate_and_set_utf8_param, ossl_param, OPENSSL_ERROR,
    OPENSSL_SUCCESS, OSSL_PROVIDER,
};

use parsec_client::error::Result as ClientResult;
use parsec_client::BasicClient;
use std::sync::Arc;

use crate::openssl_binding::{
    OSSL_ALGORITHM, OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_BUILDINFO,
    OSSL_PROV_PARAM_NAME, OSSL_PROV_PARAM_STATUS, OSSL_PROV_PARAM_VERSION,
};

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
    client: BasicClient,
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

// The null provider implementation currently doesn't supply any algorithms to the core
pub unsafe extern "C" fn parsec_provider_query(
    _prov: *mut OSSL_PROVIDER,
    _operation_id: ::std::os::raw::c_int,
    no_cache: *mut ::std::os::raw::c_int,
) -> *const OSSL_ALGORITHM {
    *no_cache = 0;
    std::ptr::null_mut()
}

// Teardowns the Provider context
pub unsafe extern "C" fn parsec_provider_teardown(provctx: *const OSSL_PROVIDER) {
    // Makes sure the provider context gets dropped
    Arc::from_raw(provctx);
}
