// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

pub use openssl_sys::OSSL_PROVIDER;
pub use parsec_openssl_sys2::openssl_binding;
pub use parsec_openssl_sys2::param as openssl_provider_param;
pub mod types;

pub use openssl2::*;

// OpenSSL expects an integer return value of 1 and 0 for success and error
pub const OPENSSL_SUCCESS: std::os::raw::c_int = 1;
pub const OPENSSL_ERROR: std::os::raw::c_int = 0;

#[macro_export]
macro_rules! ossl_dispatch {
    () => {
        OSSL_DISPATCH {
            function_id: 0,
            function: None,
        }
    };
    ($function_id:ident, $function:ident) => {
        OSSL_DISPATCH {
            function_id: $function_id as i32,
            function: Some(mem::transmute($function)),
        }
    };
}

#[macro_export]
macro_rules! ossl_param {
    () => {
        OSSL_PARAM {
            key: std::ptr::null_mut(),
            data_type: 0,
            data: std::ptr::null_mut(),
            data_size: 0,
            return_size: 0,
        }
    };
    ($key:ident, $data_type:ident) => {
        OSSL_PARAM {
            key: $key.as_ptr() as *const std::os::raw::c_char,
            data_type: $data_type,
            data: std::ptr::null_mut(),
            data_size: 0,
            return_size: usize::MAX,
        }
    };
}

// Finds the OpenSSL parameter type in the parameter array "params" and sets the value
// to the provider specific value
pub unsafe fn locate_and_set_utf8_param(
    openssl_param: &[u8],
    provider_param: &[u8],
    params: *mut openssl_binding::OSSL_PARAM,
) -> Result<(), Error> {
    let ptr = openssl_returns_nonnull(openssl_binding::OSSL_PARAM_locate(
        params,
        openssl_param.as_ptr() as *const std::os::raw::c_char,
    ))?;

    // OpenSSL returns OPENSSL_SUCCESS
    openssl_returns_1(openssl_binding::OSSL_PARAM_set_utf8_ptr(
        ptr,
        provider_param.as_ptr() as *const std::os::raw::c_char,
    ))?;
    Ok(())
}

// Finds the OpenSSL parameter "OSSL_PROV_PARAM_STATUS" in the parameter array "params" and sets it
// to active status
pub unsafe fn locate_and_set_provider_status_param(
    params: *mut openssl_binding::OSSL_PARAM,
) -> Result<(), Error> {
    let ptr = openssl_returns_nonnull(openssl_binding::OSSL_PARAM_locate(
        params,
        openssl_provider_param::OSSL_PROV_PARAM_STATUS.as_ptr() as *const std::os::raw::c_char,
    ))?;

    // OpenSSL returns OPENSSL_SUCCESS
    openssl_returns_1(openssl_binding::OSSL_PARAM_set_int(ptr, 1))?;
    Ok(())
}
