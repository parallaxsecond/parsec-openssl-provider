// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::missing_safety_doc)]

use std::sync::Arc;

pub use openssl_errors;
pub use parsec_openssl2;

use openssl_binding::{
    OSSL_CORE_HANDLE, OSSL_DISPATCH, OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
    OSSL_FUNC_PROVIDER_GET_PARAMS, OSSL_FUNC_PROVIDER_QUERY_OPERATION, OSSL_FUNC_PROVIDER_TEARDOWN,
};
use parsec_openssl2::openssl::error::ErrorStack;
use parsec_openssl2::types::VOID_PTR;
use parsec_openssl2::{openssl_binding, types};

mod keymgmt;
mod provider;
use provider::*;

mod catch;
use catch::r#catch;

// The init function populates the dispatch table and returns a void pointer
// to the provider context (which contains the parsec basic client).
pub unsafe fn parsec_provider_provider_init(
    _handle: *const OSSL_CORE_HANDLE,
    _in_: *const OSSL_DISPATCH,
    out: *mut *const OSSL_DISPATCH,
    provctx: types::VOID_PTR_PTR,
) -> Result<(), parsec_openssl2::Error> {
    env_logger::init();

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
        return Err(parsec_openssl2::Error::SysReturnedNull {
            inner: ErrorStack::get(),
        });
    }

    *out = DISPATCH_TABLE.as_ptr();

    match ParsecProviderContext::new("parsec-tool".to_string()) {
        Err(e) => {
            *provctx = std::ptr::null_mut();
            log::error!("[Provider Context Error]: {:?}", e);
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
    library Error("parsec_openssl_provider") {
        functions {
            PROVIDER_TEARDOWN("parsec_provider_teardown");
            PROVIDER_GETTABLE_PARAMS("parsec_provider_gettable_params");
            PROVIDER_GET_PARAMS("parsec_provider_get_params");
            PROVIDER_QUERY("parsec_provider_query");
        }

        reasons {
            MESSAGE("");
        }
    }
}
