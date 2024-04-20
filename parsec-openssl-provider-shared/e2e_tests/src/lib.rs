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
    private_key: Option<String>,
    ca_certificate: Option<String>,
    ssl_mode: SslVerifyMode,
}

impl Client {
    pub fn new(
        cert: Option<String>,
        key: Option<String>,
        ca: Option<String>,
        mode: SslVerifyMode,
    ) -> Client {
        Client {
            ssl_method: SslMethod::tls_client(),
            certificate: cert,
            private_key: key,
            ca_certificate: ca,
            ssl_mode: mode,
        }
    }

    // ToDo: This needs to modified in the future to use the PKey object from parsec provider
    // Uses all the Client configurations to build a SslContext object
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

    // Creates a TCP stream and initiates a TLS handshake to the server
    pub fn connect(mut self, addr: SocketAddr) {
        let socket = TcpStream::connect(addr).unwrap();
        let client_ctx = self.build();
        let ssl = Ssl::new(&client_ctx).unwrap();
        let mut channel = ssl.connect(socket).unwrap();
        channel.read_exact(&mut [0]).unwrap();
    }
}
