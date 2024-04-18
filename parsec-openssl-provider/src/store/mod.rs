use crate::openssl_bindings::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string, OSSL_ALGORITHM, OSSL_CALLBACK, OSSL_CORE_BIO, OSSL_DISPATCH,
    OSSL_FUNC_STORE_ATTACH, OSSL_FUNC_STORE_CLOSE, OSSL_FUNC_STORE_EOF, OSSL_FUNC_STORE_LOAD,
    OSSL_FUNC_STORE_OPEN, OSSL_OBJECT_PARAM_DATA, OSSL_OBJECT_PARAM_DATA_TYPE,
    OSSL_OBJECT_PARAM_TYPE, OSSL_OBJECT_PKEY, OSSL_PARAM, OSSL_PASSPHRASE_CALLBACK,
};
use crate::{
    ParsecProviderContext, PARSEC_PROVIDER_DFLT_PROPERTIES,
};
use parsec_client::core::interface::operations::list_keys::KeyInfo;
use parsec_client::core::interface::operations::psa_key_attributes::{EccFamily, Type};
use parsec_openssl2::types::VOID_PTR;
use parsec_openssl2::*;

const PARSEC_PROVIDER_STORE_NAME: &[u8; 7] = b"parsec\0";
const PARSEC_PROVIDER_DESCRIPTION_STORE: &[u8; 17] = b"Parsec URI Store\0";
const PARSEC_PROVIDER_RSA: &[u8; 4] = b"RSA\0";
const PARSEC_PROVIDER_ECDSA: &[u8; 3] = b"EC\0";

use std::sync::{Arc, RwLock};

struct ParsecProviderStoreContext {
    provctx: Arc<ParsecProviderContext>,
    keys: Vec<KeyInfo>,
    index: usize,
}

impl ParsecProviderStoreContext {
    pub fn new(provctx: Arc<ParsecProviderContext>, keys: Vec<KeyInfo>) -> Self {
        ParsecProviderStoreContext {
            provctx: provctx.clone(),
            keys,
            index: 0,
        }
    }

    fn increment_iterator(&mut self) {
        if !self.is_eof() {
            self.index += 1;
        }
    }

    pub fn get_next_key(&self) -> KeyInfo {
        self.keys[self.index].clone()
    }

    pub fn is_eof(&self) -> bool {
        self.index >= self.keys.len()
    }
}

/*
should create a provider side context with data based on the input uri. The implementation is entirely responsible for
the interpretation of the URI.
*/
unsafe extern "C" fn parsec_provider_store_open(
    provctx: VOID_PTR,
    _uri: *const std::os::raw::c_char,
) -> VOID_PTR {
    let prov = Arc::from_raw(provctx as *const ParsecProviderContext);
    match prov.get_client().list_keys() {
        Ok(keys) => {
            let store_context = RwLock::new(ParsecProviderStoreContext::new(prov, keys));
            Arc::into_raw(Arc::new(store_context)) as VOID_PTR
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

/*
loads the next object from the URI opened by OSSL_FUNC_store_open(), creates an object abstraction for it
(see provider-object), and calls object_cb with it as well as object_cbarg. object_cb will then interpret the object
abstraction and do what it can to wrap it or decode it into an OpenSSL structure. In case a passphrase needs to be
prompted to unlock an object, pw_cb should be called.
*/
unsafe extern "C" fn parsec_provider_store_load(
    loaderctx: VOID_PTR,
    object_cb: unsafe extern "C" fn(*const OSSL_PARAM, VOID_PTR) -> i32,
    object_cbarg: VOID_PTR,
    _pw_cb: *const OSSL_PASSPHRASE_CALLBACK,
    _pw_cbarg: VOID_PTR,
) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_STORE_LOAD), || {
        if loaderctx.is_null() {
            return Err("loaderctx should not be NULL".into());
        }

        Arc::increment_strong_count(loaderctx as *const RwLock<ParsecProviderStoreContext>);
        let ctx = Arc::from_raw(loaderctx as *const RwLock<ParsecProviderStoreContext>);

        let (key, key_attrs) = {
            let mut ctx_writer = ctx.write().unwrap();
            let key = ctx_writer.get_next_key();
            ctx_writer.increment_iterator();
            let key_attrs = ctx_writer
                .provctx
                .get_client()
                .key_attributes(key.name.as_str())
                .map_err(|e| format!("Failed to get specified key's attributes: {}", e))?;
            (key, key_attrs)
        };
        let (data_type_ptr, _data_type_len) = match key_attrs.key_type {
            Type::RsaKeyPair => Ok((
                PARSEC_PROVIDER_RSA.as_ptr(),
                PARSEC_PROVIDER_RSA.len(),
            )),
            Type::EccKeyPair {
                curve_family: EccFamily::SecpR1,
            } => Ok((
                PARSEC_PROVIDER_ECDSA.as_ptr(),
                PARSEC_PROVIDER_ECDSA.len(),
            )),
            _ => Err("Key type not recognized".to_string()),
        }?;
        let mut obj_type = OSSL_OBJECT_PKEY as isize;
        let obj_type_ref = &mut obj_type;
        let obj_type_ptr = obj_type_ref as *mut isize;
        let params: [OSSL_PARAM; 4] = [
            OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE.as_ptr() as _, obj_type_ptr as _),
            OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_TYPE.as_ptr() as _,
                data_type_ptr as *mut std::os::raw::c_char,
                0,
            ),
            OSSL_PARAM_construct_octet_string(
                OSSL_OBJECT_PARAM_DATA.as_ptr() as _,
                key.name.as_ptr() as VOID_PTR,
                key.name.len(),
            ),
            OSSL_PARAM_construct_end(),
        ];
        println!("object_cbarg.is_null(): {}", object_cbarg.is_null());
        let result = object_cb(params.as_ptr(), object_cbarg);
        println!("callback result: {}", result);
        Ok(result)
        // match object_cb {
        //     Some(callback) => {
        //         println!("object_cbarg.is_null(): {}", object_cbarg.is_null());
        //         let result = callback(params.as_ptr(), object_cbarg);
        //         println!("callback result: {}", result);
        //         Ok(result)
        //     }
        //     None => Err("object_cb is not set".into()),
        // }
    });
    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
}

/*
indicates if the end of the set of objects from the URI has been reached. When that happens,
there's no point trying to do any further loading.
*/
unsafe extern "C" fn parsec_provider_store_eof(loaderctx: VOID_PTR) -> std::os::raw::c_int {
    let result = super::r#catch(Some(|| super::Error::PROVIDER_STORE_EOF), || {
        if loaderctx.is_null() {
            return Err("loaderctx should not be NULL".into());
        }
        Arc::increment_strong_count(loaderctx as *const RwLock<ParsecProviderStoreContext>);
        let ctx = Arc::from_raw(loaderctx as *const RwLock<ParsecProviderStoreContext>);
        let ctx_reader = ctx.read().unwrap();
        if ctx_reader.is_eof() {
            Ok(OPENSSL_SUCCESS)
        } else {
            Err("Not EOF".into())
        }
    });
    match result {
        Ok(result) => result,
        Err(()) => OPENSSL_ERROR,
    }
}

/*
should create a provider side context with the core BIO bio attached. This is an alternative to using a URI to find
storage, supporting OSSL_STORE_attach.
*/
unsafe extern "C" fn parsec_provider_store_attach(
    _provctx: VOID_PTR,
    _bio: *const OSSL_CORE_BIO,
) -> VOID_PTR {
    std::ptr::null_mut()
}

type StoreOpenPtr = unsafe extern "C" fn(VOID_PTR, *const std::os::raw::c_char) -> VOID_PTR;
type StoreClosePtr = unsafe extern "C" fn(VOID_PTR) -> std::os::raw::c_int;
type StoreEofPtr = unsafe extern "C" fn(VOID_PTR) -> std::os::raw::c_int;
type StoreLoadPtr = unsafe extern "C" fn(
    VOID_PTR,
    unsafe extern "C" fn(*const OSSL_PARAM, VOID_PTR) -> i32,
    VOID_PTR,
    *const OSSL_PASSPHRASE_CALLBACK,
    VOID_PTR,
) -> std::os::raw::c_int;
type StoreAttachPtr = unsafe extern "C" fn(VOID_PTR, *const OSSL_CORE_BIO) -> VOID_PTR;

const OSSL_FUNC_STORE_OPEN_PTR: StoreOpenPtr = parsec_provider_store_open;
const OSSL_FUNC_STORE_CLOSE_PTR: StoreClosePtr = parsec_provider_store_close;
const OSSL_FUNC_STORE_EOF_PTR: StoreEofPtr = parsec_provider_store_eof;
const OSSL_FUNC_STORE_LOAD_PTR: StoreLoadPtr = parsec_provider_store_load;
const OSSL_FUNC_STORE_ATTACH_PTR: StoreAttachPtr = parsec_provider_store_attach;

const PARSEC_PROVIDER_STORE_IMPL: [OSSL_DISPATCH; 6] = [
    unsafe { ossl_dispatch!(OSSL_FUNC_STORE_OPEN, OSSL_FUNC_STORE_OPEN_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_STORE_CLOSE, OSSL_FUNC_STORE_CLOSE_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_STORE_LOAD, OSSL_FUNC_STORE_LOAD_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_STORE_EOF, OSSL_FUNC_STORE_EOF_PTR) },
    unsafe { ossl_dispatch!(OSSL_FUNC_STORE_ATTACH, OSSL_FUNC_STORE_ATTACH_PTR) },
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
