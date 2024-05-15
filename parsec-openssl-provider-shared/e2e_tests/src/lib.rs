// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::missing_safety_doc)]

// Needed to access as_ptr function for LibCtx
pub use foreign_types_shared::ForeignType;
pub use openssl::ssl::{Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode};
pub use parsec_openssl_provider::parsec_openssl2::openssl::{lib_ctx::LibCtx, provider::Provider};
pub use parsec_openssl_provider::parsec_openssl2::openssl_bindings::*;
use parsec_openssl_provider::parsec_openssl2::openssl_returns_1;
use parsec_openssl_provider::PARSEC_PROVIDER_DFLT_PROPERTIES;
pub use std::io::{Read, Write};
pub use std::net::{SocketAddr, TcpListener, TcpStream};
pub use std::thread::{self, JoinHandle};

use openssl::pkey::Private;
use parsec_openssl_provider::parsec_openssl2::ossl_param;
use parsec_openssl_provider::PARSEC_PROVIDER_KEY_NAME;

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
        PARSEC_PROVIDER_DFLT_PROPERTIES.as_ptr() as *const ::std::os::raw::c_char,
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

// Server object with configuration needed for TLS handshake
pub struct Server {
    ssl_method: SslMethod,
    certificate: Option<String>,
    private_key: Option<String>,
    ca_certificate: Option<String>,
    ssl_mode: SslVerifyMode,
}

impl Server {
    pub fn new(
        cert: Option<String>,
        key: Option<String>,
        ca: Option<String>,
        mode: SslVerifyMode,
    ) -> Server {
        Server {
            ssl_method: SslMethod::tls_server(),
            certificate: cert,
            private_key: key,
            ca_certificate: ca,
            ssl_mode: mode,
        }
    }

    // Uses all the Server configurations to build a SslContext object
    pub fn build(&mut self) -> SslContext {
        let mut ctx_builder = SslContext::builder(self.ssl_method).unwrap();
        if let Some(certificate) = &self.certificate {
            ctx_builder
                .set_certificate_file(certificate, SslFiletype::PEM)
                .unwrap();
        }
        if let Some(key) = &self.private_key {
            ctx_builder
                .set_private_key_file(key, SslFiletype::PEM)
                .unwrap();
        }
        if let Some(ca_cert) = &self.ca_certificate {
            ctx_builder.set_ca_file(ca_cert).unwrap();
        }
        ctx_builder.set_verify(self.ssl_mode);
        ctx_builder.build()
    }

    // Opens a TCP stream listener and accepts any incoming SSL requests
    // coming from client. The server waits in a separate thread and returns
    // the handle to the caller.
    pub fn accept(mut self, listener: TcpListener) {
        let _handle = thread::spawn(move || {
            let server_context = self.build();
            let stream = listener.accept().unwrap().0;
            let ssl = Ssl::new(&server_context).unwrap();
            let handshake_result = ssl.accept(stream);
            let mut stream = handshake_result.unwrap();
            stream.write_all(&[0]).unwrap();
        });
    }
}

// Client object with configuration needed for TLS handshake
pub struct Client {
    ssl_method: SslMethod,
    certificate: Option<String>,
    private_key_name: Option<String>,
    ca_certificate: Option<String>,
    ssl_mode: SslVerifyMode,
}

impl Client {
    pub fn new(
        cert: Option<String>,
        key_name: Option<String>,
        ca: Option<String>,
        mode: SslVerifyMode,
    ) -> Client {
        Client {
            ssl_method: SslMethod::tls_client(),
            certificate: cert,
            private_key_name: key_name,
            ca_certificate: ca,
            ssl_mode: mode,
        }
    }

    // Creates a TCP stream and initiates a TLS handshake to the server
    pub fn connect(self, addr: SocketAddr, key_type: &[u8]) {
        unsafe {
            let provider_path = String::from("../../target/debug/");
            let provider_name = String::from("libparsec_openssl_provider_shared");
            let lib_ctx = LibCtx::new().unwrap();
            let _provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

            let mut parsec_pkey: *mut EVP_PKEY = std::ptr::null_mut();

            let mut ctx_builder = SslContextBuilder::new(self.ssl_method).unwrap();

            if let Some(key) = &self.private_key_name {
                let mut param = ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, key);
                load_key(&lib_ctx, &mut param, &mut parsec_pkey, key_type);

                let key: openssl::pkey::PKey<Private> =
                    openssl::pkey::PKey::from_ptr(parsec_pkey as _);
                ctx_builder.set_private_key(&key).unwrap();
            }

            if let Some(certificate) = &self.certificate {
                ctx_builder
                    .set_certificate_file(certificate, SslFiletype::PEM)
                    .unwrap();
            }
            if let Some(ca_cert) = &self.ca_certificate {
                ctx_builder.set_ca_file(ca_cert).unwrap();
            }

            ctx_builder.set_verify(self.ssl_mode);

            let client_ctx = ctx_builder.build();
            let socket = TcpStream::connect(addr).unwrap();
            let ssl = Ssl::new(&client_ctx).unwrap();
            let mut s = ssl.connect(socket).unwrap();
            s.read_exact(&mut [0]).unwrap();
        }
    }
}

pub fn check_mismatched_key_certificate(key: String, certificate: String, key_type: &[u8]) {
    unsafe {
        let provider_path = String::from("../../target/debug/");
        let provider_name = String::from("libparsec_openssl_provider_shared");
        let lib_ctx = LibCtx::new().unwrap();
        let _provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

        let mut parsec_pkey: *mut EVP_PKEY = std::ptr::null_mut();

        let mut ctx_builder = SslContextBuilder::new(SslMethod::tls_client()).unwrap();

        ctx_builder
            .set_certificate_file(certificate, SslFiletype::PEM)
            .unwrap();

        let mut param = ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, key);
        load_key(&lib_ctx, &mut param, &mut parsec_pkey, key_type);

        let key: openssl::pkey::PKey<Private> = openssl::pkey::PKey::from_ptr(parsec_pkey as _);

        // The match function gets called here to compare public and private key and it should throw an error.
        ctx_builder.set_private_key(&key).unwrap_err();
    }
}
