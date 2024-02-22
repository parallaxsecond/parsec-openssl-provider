// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use parsec_openssl_provider::{openssl_errors, parsec_provider_provider_init};

use parsec_openssl_provider::parsec_openssl2::openssl_binding::{OSSL_CORE_HANDLE, OSSL_DISPATCH};
use parsec_openssl_provider::parsec_openssl2::types::VOID_PTR_PTR;
use parsec_openssl_provider::parsec_openssl2::{OPENSSL_ERROR, OPENSSL_SUCCESS};

mod catch;
use catch::r#catch;

#[no_mangle]
// The function name needs to be unique for dynamic libraries as the openssl core
// looks for OSSL_provider_init symbol while loading the provider.
unsafe extern "C" fn OSSL_provider_init(
    handle: *const OSSL_CORE_HANDLE,
    in_: *const OSSL_DISPATCH,
    out: *mut *const OSSL_DISPATCH,
    provctx: VOID_PTR_PTR,
) -> ::std::os::raw::c_int {
    let result = r#catch(Some(|| Error::PROVIDER_INIT), || {
        parsec_provider_provider_init(handle, in_, out, provctx)?;

        Ok(OPENSSL_SUCCESS)
    });
    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
}

openssl_errors::openssl_errors! {
    #[allow(clippy::empty_enum)]
    library Error("parsec_openssl_provider_shared") {
        functions {
            PROVIDER_INIT("parsec_provider_init");
        }

        reasons {
            MESSAGE("");
        }
    }
}
