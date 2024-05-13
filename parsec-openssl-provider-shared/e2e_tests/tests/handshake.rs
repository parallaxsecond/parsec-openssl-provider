// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::*;
use foreign_types_shared::ForeignTypeRef;
use openssl::pkey::Private;
use openssl::ssl::SslMode;
use openssl::x509::X509Name;
use parsec_openssl_provider::parsec_openssl2::{
    openssl_bindings, openssl_returns_1, openssl_returns_nonnull, openssl_returns_nonnull_const,
    ossl_param,
};
use parsec_openssl_provider::PARSEC_PROVIDER_KEY_NAME;
use parsec_openssl_provider::PARSEC_PROVIDER_RSA_NAME;

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

const DEFAULT_PROVIDER_DFLT_PROPERTIES: &[u8; 18] = b"?provider=default\0";
const PARSEC_PROVIDER_DFLT_PROPERTIES1: &[u8; 17] = b"?provider=parsec\0";
const PARSEC_PROVIDER_DFLT_PROPERTIES: &[u8; 16] = b"provider=parsec\0";
const RSA: &[u8; 8] = b"RSA-PSS\0";
#[test]
fn test_handshake_rsa123() {
    let provider_path = String::from("../../target/debug/");
    let provider_name = String::from("libparsec_openssl_provider_shared");
    // /let null = std::ptr::null();

    unsafe {
        let mut server_ctx_builder = SslContext::builder(SslMethod::tls_server()).unwrap();
        //let mut server_ctx_builder = SslContextBuilder::from_ptr(ssl_ctx as _ );
        server_ctx_builder
            .set_certificate_file(
                "/tmp/parsec-openssl-provider/tests/tls/server/server_cert.pem",
                SslFiletype::PEM,
            )
            .unwrap();
        server_ctx_builder
            .set_private_key_file(
                "/tmp/parsec-openssl-provider/tests/tls/server/server_priv_key.pem",
                SslFiletype::PEM,
            )
            .unwrap();

        server_ctx_builder
            .set_ca_file("/tmp/parsec-openssl-provider/tests/tls/ca/ca_cert.pem")
            .unwrap();
        server_ctx_builder.set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);
        //server_ctx_builder.set_sigalgs_list("RSA+SHA256");

        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let server_context = server_ctx_builder.build();
        let server_handle = thread::spawn(move || {
            let socket = socket.accept().unwrap().0;
            let mut ssl = Ssl::new(&server_context).unwrap();
            let r = ssl.accept(socket);

            let mut socket = r.unwrap();
            socket.write_all(&[0]).unwrap();
        });

        let lib_ctx1 = OSSL_LIB_CTX_get0_global_default();
        let lib_ctx = LibCtx::from_ptr(lib_ctx1 as _);
        Provider::load(Some(&lib_ctx), "default").unwrap();
        let _provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

        let key_name = String::from("PARSEC_TEST_RSA_KEY");

        let mut param = ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, key_name);

        let mut parsec_pkey: *mut EVP_PKEY = std::ptr::null_mut();
        load_key(&lib_ctx, &mut param, &mut parsec_pkey, RSA);

        //let null = std::ptr::null();

        let mut ssl_ctx = SSL_CTX_new_ex(
            //std::ptr::null_mut() as _,
            lib_ctx.as_ptr() as _,
            DEFAULT_PROVIDER_DFLT_PROPERTIES.as_ptr() as _,
            //null as _,
            (SslMethod::tls_client()).as_ptr() as _,
        );
        if ssl_ctx == std::ptr::null_mut() {
            println!("{:?}", openssl::error::ErrorStack::get());
            panic!();
        }

        //let mut client_ctx_builder = SslContext::builder(SslMethod::tls_client()).unwrap();
        let mut client_ctx_builder = SslContextBuilder::from_ptr(ssl_ctx as _);
        //let mut client_ctx_builder = SslContextBuilder::from_ptr(ssl_ctx as _);

        println!("Loading certificate now??");
        client_ctx_builder
            .set_certificate_file(
                // "/tmp/parsec-openssl-provider/tests/tls/client/client_cert.pem",
                "/tmp/parsec-openssl-provider/tests/tls/client/client_cert.pem",
                SslFiletype::PEM,
            )
            .unwrap();
        // client_ctx_builder
        //     .set_private_key_file(
        //         "/tmp/parsec-openssl-provider/tests/tls/client/client_priv_key.pem",
        //         SslFiletype::PEM,
        //     )
        //     .unwrap();
        println!("Certificate is loaded now!!");
        //let id = EVP_PKEY_get_base_id(parsec_pkey as _);
        //let priv_key =
        // PEM_read_PrivateKey();
        //println!("is is {}",id);
        let key: openssl::pkey::PKey<Private> = openssl::pkey::PKey::from_ptr(parsec_pkey as _);
        client_ctx_builder.set_private_key(&key).unwrap();

        client_ctx_builder.set_verify(SslVerifyMode::PEER);

        client_ctx_builder
            .set_ca_file("/tmp/parsec-openssl-provider/tests/tls/ca/ca_cert.pem")
            .unwrap();
        // let cert_store = client_ctx_builder.cert_store();
        // let store = cert_store.as_ptr();
        //client_ctx_builder.check_private_key().unwrap();
        //client_ctx_builder.set_sigalgs_list("rsa_pkcs1_sha256");
        // let res = SSL_CTX_check_private_key(client_ctx_builder.as_ptr() as _);
        // println!("res is {}", res);
        //client_ctx_builder.set_mode(SslMode::AUTO_RETRY);
        //client_ctx_builder.set_verify_depth(1);
        let client_ctx = client_ctx_builder.build();

        // if store == std::ptr::null_mut() {
        //     println!("store is null");
        // } else {
        //     println!("We have a store");
        // }
        let socket = TcpStream::connect(addr).unwrap();
        let mut ssl = Ssl::new(&client_ctx).unwrap();
        let res = SSL_get_certificate(ssl.as_ptr() as _);
        //SSL_set1_sigalgs_list("rsa_pkcs1_sha256");
        //SSL_ctrl(ssl.as_ptr() as _,SSL_CTRL_SET_SIGALGS_LIST.try_into().unwrap(),0,RSA_PKCS1.as_ptr() as _);

        if (res == std::ptr::null_mut()) {
            println!("No certificate in SSL object");
        } else {
            println!("SSL has certificate!!");
        }
        //let test_key = SSL_get_privatekey(ssl.as_ptr() as _);
        let test_key = ssl.private_key();
        //println!("test_key {:?}", test_key.unwrap());
        println!("test_key is {}", test_key.is_some());
        println!("test_key id is {:?}", test_key.expect("REASON").id());
        println!("test_key size is {:?}", test_key.expect("REASON").size());
        println!("test_key bits is {:?}", test_key.expect("REASON").bits());
        println!(
            "test_key security_bits is {:?}",
            test_key.expect("REASON").security_bits()
        );

        let test_certificate = ssl.certificate();
        println!("test_certificate is {}", test_certificate.is_some());
        // let id = EVP_PKEY_get_base_id(test_key as _);

        // println!("iDDD is {}",id);
        let mut s = ssl.connect(socket).unwrap();
        s.read_exact(&mut [0]).unwrap();
        println!("Join server!!");
        server_handle.join().unwrap();

        //EVP_PKEY_free(parsec_pkey);
    }
}
