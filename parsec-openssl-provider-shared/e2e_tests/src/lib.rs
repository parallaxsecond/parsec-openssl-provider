// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::missing_safety_doc)]

// Needed to access as_ptr function for LibCtx
pub use foreign_types_shared::ForeignType;
pub use parsec_openssl_provider::parsec_openssl2::openssl::{lib_ctx::LibCtx, provider::Provider};
pub use parsec_openssl_provider::parsec_openssl2::openssl_bindings::*;
use parsec_openssl_provider::parsec_openssl2::openssl_returns_1;

// These needs to be replaced with consts from the key management module
pub const PARSEC_PROVIDER_RSA: &[u8; 4] = b"RSA\0";
pub const PARSEC_PROVIDER_ECDSA: &[u8; 6] = b"ECDSA\0";
pub const PARSEC_PROVIDER_PROPERTY: &[u8; 16] = b"provider=parsec\0";

// Loads a provider into the given library context
pub fn load_provider(lib_ctx: &LibCtx, provider_name: &str, provider_path: String) -> Provider {
    assert!(Provider::set_default_search_path(Some(lib_ctx), &provider_path).is_ok());
    Provider::load(Some(lib_ctx), provider_name).unwrap()
}

// Loads a key using the given library context with loaded provider. The param should contain the necessary
// parameters based on the provider that we are loading.
pub unsafe fn load_key(
    lib_ctx: &LibCtx,
    param: *mut OSSL_PARAM,
    parsec_pkey: *mut *mut EVP_PKEY,
    key_type: &[u8],
) {
    let evp_ctx: *mut EVP_PKEY_CTX = EVP_PKEY_CTX_new_from_name(
        lib_ctx.as_ptr() as *mut ossl_lib_ctx_st,
        key_type.as_ptr() as *const ::std::os::raw::c_char,
        PARSEC_PROVIDER_PROPERTY.as_ptr() as *const ::std::os::raw::c_char,
    );
    assert_ne!(evp_ctx, std::ptr::null_mut());
    openssl_returns_1(EVP_PKEY_fromdata_init(evp_ctx)).unwrap();
    openssl_returns_1(EVP_PKEY_fromdata(
        evp_ctx,
        parsec_pkey as _,
        EVP_PKEY_KEY_PARAMETERS.try_into().unwrap(),
        param,
    ))
    .unwrap();
    assert_ne!(*parsec_pkey, std::ptr::null_mut());

    EVP_PKEY_CTX_free(evp_ctx);
}
