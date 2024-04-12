// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use e2e_tests::*;
use parsec_openssl_provider::parsec_openssl2::{
    openssl_bindings, openssl_returns_1, openssl_returns_nonnull, openssl_returns_nonnull_const,
    ossl_param,
};
use std::ffi::CStr;

// Simple test to load a provider. Test fails if load_provider function reports error
#[test]
fn test_loading_parsec_provider() {
    let provider_path = String::from("../../target/debug");
    let provider_name = String::from("libparsec_openssl_provider_shared");
    let lib_ctx: LibCtx = LibCtx::new().unwrap();
    let _provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);
}

// Fetch the provider name from the OSSL interface "OSSL_PROVIDER_get0_name"
#[test]
fn test_parsec_provider_name() {
    let provider_path = String::from("../../target/debug/");
    let provider_name = String::from("libparsec_openssl_provider_shared");
    let lib_ctx: LibCtx = LibCtx::new().unwrap();
    let provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

    unsafe {
        let prov_name = OSSL_PROVIDER_get0_name(provider.as_ptr() as *const ossl_provider_st);
        let prov_name = CStr::from_ptr(prov_name);
        assert_eq!(prov_name.to_str().unwrap(), provider_name);
    }
}

// Checks if the parsec provider returns the expected list in the gettable param
// structure
#[test]
fn test_parsec_provider_gettable_param() {
    let provider_path = String::from("../../target/debug/");
    let provider_name = String::from("libparsec_openssl_provider_shared");
    let lib_ctx: LibCtx = LibCtx::new().unwrap();
    let provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);
    unsafe {
        let gettable_params: *const OSSL_PARAM =
            OSSL_PROVIDER_gettable_params(provider.as_ptr() as *const ossl_provider_st);

        // Checks if the returned structure contains OSSL_PROV_PARAM_NAME
        openssl_returns_nonnull(openssl_bindings::OSSL_PARAM_locate(
            gettable_params as _,
            openssl_bindings::OSSL_PROV_PARAM_NAME.as_ptr() as *const std::os::raw::c_char,
        ))
        .unwrap();

        // Checks if the returned structure contains OSSL_PROV_PARAM_VERSION
        openssl_returns_nonnull(openssl_bindings::OSSL_PARAM_locate(
            gettable_params as _,
            openssl_bindings::OSSL_PROV_PARAM_VERSION.as_ptr() as *const std::os::raw::c_char,
        ))
        .unwrap();

        // Checks if the returned structure contains OSSL_PROV_PARAM_STATUS
        openssl_returns_nonnull(openssl_bindings::OSSL_PARAM_locate(
            gettable_params as _,
            openssl_bindings::OSSL_PROV_PARAM_STATUS.as_ptr() as *const std::os::raw::c_char,
        ))
        .unwrap();
    }
}

// Fetch the supported params from the parsec provider and compares if its as expected
#[test]
fn test_parsec_provider_get_param() {
    let provider_path = String::from("../../target/debug/");
    let provider_name = String::from("libparsec_openssl_provider_shared");
    let lib_ctx: LibCtx = LibCtx::new().unwrap();
    let provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

    let mut prov_name: *mut i8 = std::ptr::null_mut();
    let mut prov_version: *mut i8 = std::ptr::null_mut();
    let mut prov_status: i32 = 0;
    unsafe {
        let mut params: [OSSL_PARAM; 4] =
            [ossl_param!(), ossl_param!(), ossl_param!(), ossl_param!()];

        // Construct the 3 parameters
        params[0] = OSSL_PARAM_construct_utf8_ptr(
            openssl_bindings::OSSL_PROV_PARAM_NAME.as_ptr() as _,
            &mut prov_name,
            0,
        );
        params[1] = OSSL_PARAM_construct_utf8_ptr(
            openssl_bindings::OSSL_PROV_PARAM_VERSION.as_ptr() as _,
            &mut prov_version,
            0,
        );
        params[2] = OSSL_PARAM_construct_int(
            openssl_bindings::OSSL_PROV_PARAM_STATUS.as_ptr() as _,
            &mut prov_status as *mut i32,
        );

        // Ensure the structure is unpopulated
        assert_eq!(OSSL_PARAM_modified(&params as _), 0);
        assert_eq!(OSSL_PARAM_modified(&params[1] as _), 0);
        assert_eq!(OSSL_PARAM_modified(&params[2] as _), 0);

        // Fetch the providers
        openssl_returns_1(OSSL_PROVIDER_get_params(
            provider.as_ptr() as *const ossl_provider_st,
            params.as_ptr() as *mut OSSL_PARAM,
        ))
        .unwrap();

        // Ensure the structure is populated by the provider
        openssl_returns_1(OSSL_PARAM_modified(&params as _)).unwrap();
        openssl_returns_1(OSSL_PARAM_modified(&params[1] as _)).unwrap();
        openssl_returns_1(OSSL_PARAM_modified(&params[2] as _)).unwrap();

        // Verify the returned provider parameters
        let prov_name = CStr::from_ptr(prov_name);
        let prov_name = prov_name.to_str().unwrap();
        assert_eq!(prov_name, "Parsec OpenSSL Provider");

        let prov_version = CStr::from_ptr(prov_version);
        let prov_version = prov_version.to_str().unwrap();
        assert_eq!(prov_version, "0.1.0");
    }
}

// Verifies that the provider is able to return a non NULL pointer when queried for
// a supported function
#[test]
fn test_provider_query_supported() {
    let provider_path = String::from("../../target/debug");
    let provider_name = String::from("libparsec_openssl_provider_shared");
    let lib_ctx: LibCtx = LibCtx::new().unwrap();
    let provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

    let mut no_cache: i32 = 0;
    unsafe {
        openssl_returns_nonnull_const(OSSL_PROVIDER_query_operation(
            provider.as_ptr() as _,
            OSSL_OP_KEYMGMT.try_into().unwrap(),
            &mut no_cache as _,
        ))
        .unwrap();
    }
}

// Verifies that the provider is able to return a NULL pointer when queried for
// an unsupported function
#[test]
fn test_provider_query_unsupported() {
    let provider_path = String::from("../../target/debug");
    let provider_name = String::from("libparsec_openssl_provider_shared");
    let lib_ctx: LibCtx = LibCtx::new().unwrap();
    let provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

    let mut no_cache: i32 = 0;
    unsafe {
        assert_eq!(
            OSSL_PROVIDER_query_operation(
                provider.as_ptr() as _,
                OSSL_OP_RAND.try_into().unwrap(),
                &mut no_cache as _,
            ),
            std::ptr::null_mut()
        );
    }
}
