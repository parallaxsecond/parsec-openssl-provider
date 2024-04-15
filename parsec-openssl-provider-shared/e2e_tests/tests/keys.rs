// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use e2e_tests::*;
use parsec_openssl_provider::parsec_openssl2::ossl_param;
use parsec_openssl_provider::{
    PARSEC_PROVIDER_ECDSA_NAME, PARSEC_PROVIDER_KEY_NAME, PARSEC_PROVIDER_RSA_NAME,
};

// Loads RSA key from the provider
#[test]
fn test_loading_rsa_key() {
    let provider_path = String::from("../../target/debug/");
    let provider_name = String::from("libparsec_openssl_provider_shared");

    let lib_ctx: LibCtx = LibCtx::new().unwrap();
    let _provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

    // Create a key beforehand using the parsec-tool and then run the test.
    let key_name = "PARSEC_TEST_RSA_KEY".to_string();
    let mut param = ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, key_name);
    unsafe {
        let mut parsec_pkey: *mut EVP_PKEY = std::ptr::null_mut();
        load_key(
            &lib_ctx,
            &mut param,
            &mut parsec_pkey,
            PARSEC_PROVIDER_RSA_NAME,
        );

        EVP_PKEY_free(parsec_pkey);
    }
}

// Loads ECDSA key from the provider
#[test]
fn test_loading_ecdsa_key() {
    let provider_path = String::from("../../target/debug/");
    let provider_name = String::from("libparsec_openssl_provider_shared");

    let lib_ctx: LibCtx = LibCtx::new().unwrap();
    let _provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

    // Create a key beforehand using the parsec-tool and then run the test.
    let key_name = "PARSEC_TEST_ECDSA_KEY".to_string();
    let mut param = ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, key_name);
    unsafe {
        let mut parsec_pkey: *mut EVP_PKEY = std::ptr::null_mut();
        load_key(
            &lib_ctx,
            &mut param,
            &mut parsec_pkey,
            PARSEC_PROVIDER_ECDSA_NAME,
        );

        EVP_PKEY_free(parsec_pkey);
    }
}
