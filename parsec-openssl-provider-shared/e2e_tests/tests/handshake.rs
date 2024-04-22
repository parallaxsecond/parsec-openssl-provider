// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::*;
use foreign_types_shared::ForeignTypeRef;
use openssl::pkey::Private;
use openssl::x509::X509Name;
use parsec_openssl_provider::parsec_openssl2::{
    openssl_bindings, openssl_returns_1, openssl_returns_nonnull, openssl_returns_nonnull_const,
    ossl_param,
};
use parsec_openssl_provider::PARSEC_PROVIDER_KEY_NAME;
use parsec_openssl_provider::PARSEC_PROVIDER_RSA_NAME;
use openssl::ssl::SslMode;

#[test]
fn test_handshake_no_authentication() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = Server::new(
        Some(String::from("../../tests/tls/server/server_cert.pem")),
        Some(String::from("../../tests/tls/server/server_priv_key.pem")),
        Some(String::from("../../tests/tls/ca/ca_cert.pem")),
        SslVerifyMode::NONE,
    );
    server.accept(listener);

    let client = Client::new(None, None, None, SslVerifyMode::NONE);
    client.connect(addr);
}

#[should_panic]
#[test]
fn test_handshake_server_authentication_no_client_ca() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = Server::new(
        Some(String::from("../../tests/tls/server/server_cert.pem")),
        Some(String::from("../../tests/tls/server/server_priv_key.pem")),
        Some(String::from("../../tests/tls/ca/ca_cert.pem")),
        SslVerifyMode::NONE,
    );
    server.accept(listener);

    let client = Client::new(None, None, None, SslVerifyMode::PEER);
    client.connect(addr);
}

#[test]
fn test_handshake_server_authentication_with_client_ca() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = Server::new(
        Some(String::from("../../tests/tls/server/server_cert.pem")),
        Some(String::from("../../tests/tls/server/server_priv_key.pem")),
        Some(String::from("../../tests/tls/ca/ca_cert.pem")),
        SslVerifyMode::NONE,
    );
    server.accept(listener);

    let client = Client::new(
        None,
        None,
        Some(String::from("../../tests/tls/ca/ca_cert.pem")),
        SslVerifyMode::PEER,
    );
    client.connect(addr);
}

#[should_panic]
#[test]
fn test_handshake_client_authentication_with_no_client_settings() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = Server::new(
        Some(String::from("../../tests/tls/server/server_cert.pem")),
        Some(String::from("../../tests/tls/server/server_priv_key.pem")),
        Some(String::from("../../tests/tls/ca/ca_cert.pem")),
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
    );
    server.accept(listener);

    let client = Client::new(
        None,
        None,
        Some(String::from("../../tests/tls/ca/ca_cert.pem")),
        SslVerifyMode::PEER,
    );
    client.connect(addr);
}

#[should_panic]
#[test]
fn test_handshake_client_authentication_with_no_client_key() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = Server::new(
        Some(String::from("../../tests/tls/server/server_cert.pem")),
        Some(String::from("../../tests/tls/server/server_priv_key.pem")),
        Some(String::from("../../tests/tls/ca/ca_cert.pem")),
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
    );
    server.accept(listener);

    let client = Client::new(
        Some(String::from("../../tests/tls/client/client_cert.pem")),
        None,
        Some(String::from("../../tests/tls/ca/ca_cert.pem")),
        SslVerifyMode::PEER,
    );
    client.connect(addr);
}

#[test]
fn test_handshake_client_authentication() {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();

    let server = Server::new(
        Some(String::from("../../tests/tls/server/server_cert.pem")),
        Some(String::from("../../tests/tls/server/server_priv_key.pem")),
        Some(String::from("../../tests/tls/ca/ca_cert.pem")),
        SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER,
    );
    server.accept(socket);

    let client = Client::new(
        Some(String::from("../../tests/tls/client/client_cert.pem")),
        Some(String::from("../../tests/tls/client/client_priv_key.pem")),
        Some(String::from("../../tests/tls/ca/ca_cert.pem")),
        SslVerifyMode::PEER,
    );
    client.connect(addr);
}

#[should_panic]
#[test]
fn test_handshake_client_authentication_with_fake_ca() {
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();

    let server = Server::new(
        Some(String::from("../../tests/tls/server/server_cert.pem")),
        Some(String::from("../../tests/tls/server/server_priv_key.pem")),
        Some(String::from("../../tests/tls/ca/ca_cert.pem")),
        SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER,
    );
    server.accept(socket);

    let client = Client::new(
        Some(String::from("../../tests/tls/fake_client/client_cert.pem")),
        Some(String::from(
            "../../tests/tls/fake_client/client_priv_key.pem",
        )),
        Some(String::from("../../tests/tls/fake_ca/ca_cert.pem")),
        SslVerifyMode::PEER,
    );
    client.connect(addr);
}

const DEFAULT_PROVIDER_DFLT_PROPERTIES: &[u8; 17] = b"provider=default\0";
#[test]
fn test_handshake_rsa123() {
    let provider_path = String::from("../../target/debug/");
    let provider_name = String::from("libparsec_openssl_provider_shared");
    unsafe {

        let lib_ctx1 = OSSL_LIB_CTX_get0_global_default();
        let lib_ctx = LibCtx::from_ptr(lib_ctx1 as _);

        let _provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

        Provider::load(Some(&lib_ctx), "default").unwrap();

        let key_name = String::from("PARSEC_TEST_RSA_KEY");

        let mut param = ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, key_name);

        let mut parsec_pkey: *mut EVP_PKEY = std::ptr::null_mut();
        load_key(
            &lib_ctx,
            &mut param,
            &mut parsec_pkey,
            PARSEC_PROVIDER_RSA_NAME,
        );


        let mut ssl_ctx = SSL_CTX_new_ex(
            lib_ctx.as_ptr() as _,
            DEFAULT_PROVIDER_DFLT_PROPERTIES.as_ptr() as _,
            (SslMethod::tls_client()).as_ptr() as _,
        );
        if ssl_ctx == std::ptr::null_mut() {
            println!("{:?}", openssl::error::ErrorStack::get());
            panic!();
        }
	
    let server = Server::new(
        Some(String::from("../../tests/tls/server/server_cert.pem")),
        Some(String::from("../../tests/tls/server/server_priv_key.pem")),
        Some(String::from("../../tests/tls/ca/ca_cert.pem")),
        SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER,
    );
    server.accept(socket);


        let mut client_ctx_builder = SslContextBuilder::from_ptr(ssl_ctx as _);

        println!("Loading certificate now??");
        client_ctx_builder
            .set_certificate_file(
                "/tmp/parsec-openssl-provider/tests/parsec_cert.pem",
                SslFiletype::PEM,
            )
            .unwrap();
        client_ctx_builder
            .set_private_key_file(
                "/tmp/parsec-openssl-provider/tests/tls/client/client_priv_key.pem",
                SslFiletype::PEM,
            )
            .unwrap();

        let key: openssl::pkey::PKey<Private> = openssl::pkey::PKey::from_ptr(parsec_pkey as _);

        client_ctx_builder.set_private_key(&key).unwrap();


        client_ctx_builder.set_verify(SslVerifyMode::PEER);
        println!("Verify peer set on client");
        client_ctx_builder
            .set_ca_file("/tmp/parsec-openssl-provider/tests/tls/ca/ca_cert.pem")
            .unwrap();

        client_ctx_builder.check_private_key().unwrap();
        let res = SSL_CTX_check_private_key(client_ctx_builder.as_ptr() as _);


        let client_ctx = client_ctx_builder.build();


        let socket = TcpStream::connect(addr).unwrap();
        let mut ssl = Ssl::new(&client_ctx).unwrap();
        let res =SSL_get_certificate(ssl.as_ptr() as _);
        if (res == std::ptr::null_mut()){
            println!("No certificate in SSL object");
        }
        else {
            println!("SSL has certificate!!");
        }
        let mut s = ssl.connect(socket).unwrap();
        s.read_exact(&mut [0]).unwrap();
        server_handle.join().unwrap();
        
        //EVP_PKEY_free(parsec_pkey);
    }
}
