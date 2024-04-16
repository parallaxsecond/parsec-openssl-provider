use crate::openssl_bindings::{
    OSSL_ALGORITHM, OSSL_DISPATCH, OSSL_FUNC_STORE_CLOSE, OSSL_FUNC_STORE_OPEN,
};
use crate::{ParsecProviderContext, PARSEC_PROVIDER_DFLT_PROPERTIES};
use parsec_client::core::interface::operations::list_keys::KeyInfo;
use parsec_openssl2::types::VOID_PTR;
use parsec_openssl2::*;

const PARSEC_PROVIDER_STORE_NAME: &[u8; 7] = b"parsec\0";
const PARSEC_PROVIDER_DESCRIPTION_STORE: &[u8; 17] = b"Parsec URI Store\0";

use std::ffi::CStr;
use std::sync::{Arc, RwLock};

struct ParsecProviderStoreContext {
    _provctx: Arc<ParsecProviderContext>,
    _keys: Vec<KeyInfo>,
}

impl ParsecProviderStoreContext {
    pub fn new(provctx: Arc<ParsecProviderContext>, keys: Vec<KeyInfo>) -> Self {
        ParsecProviderStoreContext {
            _provctx: provctx.clone(),
            _keys: keys,
        }
    }
}

/*
should create a provider side context with data based on the input uri. The implementation is entirely responsible for
the interpretation of the URI.
*/
unsafe extern "C" fn parsec_provider_store_open(
    provctx: VOID_PTR,
    uri: *const std::os::raw::c_char,
) -> VOID_PTR {
    let prov = Arc::from_raw(provctx as *const ParsecProviderContext);
    match prov.get_client().list_keys() {
        Ok(keys) => {
            let key_name: &str =
                std::str::from_utf8_unchecked(CStr::from_ptr(uri as *const _).to_bytes());
            if keys.iter().any(|kinfo| kinfo.name == key_name) {
                let store_context = RwLock::new(ParsecProviderStoreContext::new(prov, keys));
                Arc::into_raw(Arc::new(store_context)) as VOID_PTR
            } else {
                std::ptr::null_mut()
            }
        }
        _ => std::ptr::null_mut(),
    }
}

/*
frees the provider side context ctx.
*/
unsafe extern "C" fn parsec_provider_store_close(loaderctx: VOID_PTR) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_STORE_CLOSE), || {
        if loaderctx.is_null() {
            return Err("loaderctx should not be NULL".into());
        }

        let arc_ctx = Arc::from_raw(loaderctx as *const RwLock<ParsecProviderStoreContext>);
        // A strong_count of 1 should be guaranteed by OPENSSL, as it doesn't make sense to be calling
        // free when you are still using the ctx.
        assert_eq!(1, Arc::strong_count(&arc_ctx));
        // When arc_ctx is dropped, the reference count is decremented and the memory is freed
        Ok(OPENSSL_SUCCESS)
    });
    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
}

type StoreOpenPtr = unsafe extern "C" fn(VOID_PTR, *const std::os::raw::c_char) -> VOID_PTR;
type StoreClosePtr = unsafe extern "C" fn(VOID_PTR) -> std::os::raw::c_int;

const OSSL_FUNC_STORE_OPEN_PTR: StoreOpenPtr = parsec_provider_store_open;
const OSSL_FUNC_STORE_CLOSE_PTR: StoreClosePtr = parsec_provider_store_close;

const PARSEC_PROVIDER_STORE_IMPL: [OSSL_DISPATCH; 3] = [
    unsafe { ossl_dispatch!(OSSL_FUNC_STORE_OPEN, OSSL_FUNC_STORE_OPEN_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_STORE_CLOSE, OSSL_FUNC_STORE_CLOSE_PTR) },
    ossl_dispatch!(),
];

pub const PARSEC_PROVIDER_STORE: [OSSL_ALGORITHM; 2] = [
    ossl_algorithm!(
        PARSEC_PROVIDER_STORE_NAME,
        PARSEC_PROVIDER_DFLT_PROPERTIES,
        PARSEC_PROVIDER_STORE_IMPL,
        PARSEC_PROVIDER_DESCRIPTION_STORE
    ),
    ossl_algorithm!(),
];
