// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::missing_safety_doc)]
#![deny(warnings)]

use std::sync::Arc;

pub use openssl_errors;
pub use parsec_openssl2;

use openssl_bindings::{
    OSSL_CORE_HANDLE, OSSL_DISPATCH, OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
    OSSL_FUNC_PROVIDER_GET_PARAMS, OSSL_FUNC_PROVIDER_QUERY_OPERATION, OSSL_FUNC_PROVIDER_TEARDOWN,
};
use parsec_openssl2::openssl::error::ErrorStack;
use parsec_openssl2::types::VOID_PTR;
use parsec_openssl2::{openssl_bindings, types};

mod keymgmt;
mod signature;

mod provider;
use provider::*;

mod catch;
use catch::r#catch;

// Parameter names that Providers can define
const PARSEC_PROVIDER_RSA_NAME: &[u8; 4] = b"RSA\0";
const PARSEC_PROVIDER_ECDSA_NAME: &[u8; 6] = b"ECDSA\0";
const PARSEC_PROVIDER_DESCRIPTION_RSA: &[u8; 11] = b"Parsec RSA\0";
const PARSEC_PROVIDER_DESCRIPTION_ECDSA: &[u8; 13] = b"Parsec ECDSA\0";
const PARSEC_PROVIDER_DFLT_PROPERTIES: &[u8; 16] = b"provider=parsec\0";
pub const PARSEC_PROVIDER_KEY_NAME: &[u8; 25] = b"parsec_provider_key_name\0";

// The init function populates the dispatch table and returns a void pointer
// to the provider context (which contains the parsec basic client).
pub unsafe fn parsec_provider_provider_init(
    _handle: *const OSSL_CORE_HANDLE,
    _in_: *const OSSL_DISPATCH,
    out: *mut *const OSSL_DISPATCH,
    provctx: types::VOID_PTR_PTR,
) -> Result<(), parsec_openssl2::Error> {
    let _ = env_logger::try_init();

    let parsec_provider_teardown_ptr: ProviderTeardownPtr = parsec_provider_teardown;

    let parsec_provider_gettable_params_ptr: ProviderGettableParamsPtr =
        parsec_provider_gettable_params;

    let parsec_provider_get_params_ptr: ProviderGetParamsPtr = parsec_provider_get_params;

    let parsec_provider_query_ptr: ProviderQueryPtr = parsec_provider_query;

    static mut DISPATCH_TABLE: [OSSL_DISPATCH; 5] = [parsec_openssl2::ossl_dispatch!(); 5];
    static RESULT_INIT: std::sync::Once = std::sync::Once::new();

    RESULT_INIT.call_once(|| {
        DISPATCH_TABLE = [
            parsec_openssl2::ossl_dispatch!(
                OSSL_FUNC_PROVIDER_TEARDOWN,
                parsec_provider_teardown_ptr
            ),
            parsec_openssl2::ossl_dispatch!(
                OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
                parsec_provider_gettable_params_ptr
            ),
            parsec_openssl2::ossl_dispatch!(
                OSSL_FUNC_PROVIDER_GET_PARAMS,
                parsec_provider_get_params_ptr
            ),
            parsec_openssl2::ossl_dispatch!(
                OSSL_FUNC_PROVIDER_QUERY_OPERATION,
                parsec_provider_query_ptr
            ),
            parsec_openssl2::ossl_dispatch!(),
        ];
    });

    if out.is_null() || provctx.is_null() {
        log::error!(
            "[Parsec Provider Init Error]: Neither out nor provctx parameters should be NULL"
        );
        return Err(parsec_openssl2::Error::SysReturnedNull {
            inner: ErrorStack::get(),
        });
    }

    *out = DISPATCH_TABLE.as_ptr();

    match ParsecProviderContext::new("parsec-tool".to_string()) {
        Err(e) => {
            *provctx = std::ptr::null_mut();
            log::error!("[Parsec Provider Init Error]: {:?}", e);
            return Err(parsec_openssl2::Error::SysReturnedNull {
                inner: ErrorStack::get(),
            });
        }
        Ok(ctx) => {
            let arc_context = Arc::new(ctx);
            *provctx = Arc::into_raw(arc_context) as VOID_PTR;
        }
    }

    Ok(())
}

openssl_errors::openssl_errors! {
    #[allow(clippy::empty_enum)]
    pub library Error("parsec_openssl_provider") {
        functions {
            PROVIDER_GETTABLE_PARAMS("parsec_provider_gettable_params");
            PROVIDER_GET_PARAMS("parsec_provider_get_params");
            PROVIDER_KEYMGMT_HAS("parsec_provider_kmgmt_has");
            PROVIDER_KEYMGMT_IMPORT("parsec_provider_kmgmt_import");
            PROVIDER_KEYMGMT_MATCH("parsec_provider_kmgmt_match");
            PROVIDER_KEYMGMT_SET_PARAMS("parsec_provider_kmgmt_set_params");
            PROVIDER_KEYMGMT_VALIDATE("parsec_provider_kmgmt_validate");
            PROVIDER_QUERY("parsec_provider_query");
            PROVIDER_TEARDOWN("parsec_provider_teardown");
        }

        reasons {
            MESSAGE("");
        }
    }
}

/// Assumes a "PARSEC_TEST_RSA_KEY" key has been loaded out of band through the parsec-tool
#[test]
fn test_provider_init() {
    use crate::parsec_provider_teardown;
    use parsec_openssl2::OSSL_PROVIDER;
    let handle: *const OSSL_CORE_HANDLE = std::ptr::null();
    let in_: *const OSSL_DISPATCH = std::ptr::null();
    let out: *const OSSL_DISPATCH = std::ptr::null();
    let mut provctx: types::VOID_PTR = std::ptr::null_mut();

    // Initialize the provider
    let result: Result<(), parsec_openssl2::Error> = unsafe {
        parsec_provider_provider_init(
            handle,
            in_,
            &out as *const _ as *mut _,
            &mut provctx as *mut VOID_PTR,
        )
    };

    // Get the ParsecProviderContext
    let arc_prov_ctx = provctx as *mut ParsecProviderContext;
    assert!(result.is_ok());
    let prov_context: Arc<ParsecProviderContext> = unsafe { Arc::from_raw(arc_prov_ctx) };

    // List the existing keys through the parsec client
    let keys = prov_context.get_client().list_keys().unwrap();

    assert_ne!(keys.len(), 0);

    // Find the pre-generated key.
    assert!(keys.iter().any(|x| x.name == "PARSEC_TEST_RSA_KEY"));

    unsafe {
        parsec_provider_teardown(Arc::into_raw(prov_context) as *const OSSL_PROVIDER);
    }
}
