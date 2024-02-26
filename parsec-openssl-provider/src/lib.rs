// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::mem;

pub use openssl_errors;
pub use parsec_openssl2;

use parsec_openssl2::{openssl_binding, types};

use openssl_binding::{
    OSSL_CORE_HANDLE, OSSL_DISPATCH, OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
    OSSL_FUNC_PROVIDER_GET_PARAMS, OSSL_FUNC_PROVIDER_QUERY_OPERATION,
};

mod provider;
use provider::*;

mod catch;
use catch::r#catch;

// The init function populates the dispatch table and returns a NULL pointer
// to the provider context. This needs to be changed when key management and
// crypto support is added to the provider.
pub unsafe fn parsec_provider_provider_init(
    _handle: *const OSSL_CORE_HANDLE,
    _in_: *const OSSL_DISPATCH,
    out: *mut *const OSSL_DISPATCH,
    provctx: types::VOID_PTR_PTR,
) -> Result<(), parsec_openssl2::Error> {

    env_logger::init();

    let parsec_provider_gettable_params_ptr: ProviderGettableParamsPtr =
        parsec_provider_gettable_params;

    let parsec_provider_get_params_ptr: ProviderGetParamsPtr = parsec_provider_get_params;

    let parsec_provider_query_ptr: ProviderQueryPtr = parsec_provider_query;

    static mut DISPATCH_TABLE: [OSSL_DISPATCH; 4] = [parsec_openssl2::ossl_dispatch!(); 4];
    static RESULT_INIT: std::sync::Once = std::sync::Once::new();

    RESULT_INIT.call_once(|| {
        DISPATCH_TABLE = [
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

    *out = DISPATCH_TABLE.as_ptr();
    *provctx = std::ptr::null_mut();

    Ok(())
}

openssl_errors::openssl_errors! {
    #[allow(clippy::empty_enum)]
    library Error("parsec_openssl_provider") {
        functions {
            PROVIDER_GETTABLE_PARAMS("parsec_provider_gettable_params");
            PROVIDER_GET_PARAMS("parsec_provider_get_params");
            PROVIDER_QUERY("parsec_provider_query");
        }

        reasons {
            MESSAGE("");
        }
    }
}
