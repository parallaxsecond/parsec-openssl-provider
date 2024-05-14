// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use e2e_tests::*;

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

// This is a negative test case. When a client is configured with a wrong certificate for a private
// key, the key management match function should report an error about the mismatched private key and
// public key from the x509 certificate.
#[test]
fn test_client_with_mismatched_key_and_certificate() {
    let mut ctx_builder = SslContext::builder(SslMethod::tls_client()).unwrap();

    ctx_builder
        .set_certificate_file(
            String::from("../../tests/tls/fake_client/client_cert.pem"),
            SslFiletype::PEM,
        )
        .unwrap();

    ctx_builder
        .set_private_key_file(
            String::from("../../tests/tls/client/client_priv_key.pem"),
            SslFiletype::PEM,
        )
        .unwrap_err();
}