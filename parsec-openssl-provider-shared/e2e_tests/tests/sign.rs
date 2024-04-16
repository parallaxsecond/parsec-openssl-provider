// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use e2e_tests::*;
use parsec_client::core::basic_client::BasicClient;
use parsec_client::core::interface::operations::psa_algorithm::{AsymmetricSignature, Hash};
use parsec_openssl_provider::parsec_openssl2::ossl_param;
use parsec_openssl_provider::parsec_openssl2::{openssl_returns_1, Openssl2Error};
use parsec_openssl_provider::{
    PARSEC_PROVIDER_DFLT_PROPERTIES, PARSEC_PROVIDER_ECDSA_NAME, PARSEC_PROVIDER_KEY_NAME,
    PARSEC_PROVIDER_RSA_NAME,
};
use sha2::{Digest, Sha256};

// Signs a digest using Parsec Provider and verifies the signature using the
// same key via the parsec-tool. The test only passes if the signature verification
// is a success.
fn sign_verify(
    key_name: &str,
    signature: &mut [u8],
    sign_algorithm: AsymmetricSignature,
    key_type: &[u8],
) -> Result<(), Openssl2Error> {
    // These are a backup to be used with different modalities of EVP_PKEY_sign
    let mut other_signature: Vec<u8> = vec![0; signature.len()];
    let mut other_len = signature.len();

    let provider_path = String::from("../../target/debug/");
    let provider_name = String::from("libparsec_openssl_provider_shared");

    let lib_ctx: LibCtx = LibCtx::new().unwrap();
    let _provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

    let mut param = ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, key_name);

    let mut hasher = Sha256::new();
    hasher.update(b"Parsec OpenSSL Provider");
    let hash = hasher.finalize();

    unsafe {
        let mut parsec_pkey: *mut EVP_PKEY = std::ptr::null_mut();
        load_key(&lib_ctx, &mut param, &mut parsec_pkey, key_type);

        let evp_ctx: *mut EVP_PKEY_CTX = EVP_PKEY_CTX_new_from_pkey(
            lib_ctx.as_ptr() as *mut ossl_lib_ctx_st,
            parsec_pkey,
            PARSEC_PROVIDER_DFLT_PROPERTIES.as_ptr() as *const ::std::os::raw::c_char,
        );

        let mut sign_len = 0;

        // Initialize and perform signing operation using EVP interfaces
        openssl_returns_1(EVP_PKEY_sign_init(evp_ctx)).unwrap();

        openssl_returns_1(EVP_PKEY_sign(
            evp_ctx,
            std::ptr::null_mut(),
            &mut sign_len,
            hash.as_ptr(),
            hash.len(),
        ))
        .unwrap();
        assert_eq!(sign_len, signature.len());

        openssl_returns_1(EVP_PKEY_sign(
            evp_ctx,
            signature.as_mut_ptr(),
            &mut sign_len,
            hash.as_ptr(),
            hash.len(),
        ))
        .unwrap();

        openssl_returns_1(EVP_PKEY_sign(
            evp_ctx,
            other_signature.as_mut_ptr(),
            &mut other_len,
            hash.as_ptr(),
            hash.len(),
        ))
        .unwrap();

        EVP_PKEY_free(parsec_pkey);
    }

    let client = BasicClient::new(Some(String::from("parsec-tool"))).unwrap();

    client
        .psa_verify_hash(key_name, &hash, sign_algorithm, signature)
        .unwrap();
    client
        .psa_verify_hash(
            key_name,
            &hash,
            sign_algorithm,
            other_signature.as_mut_slice(),
        )
        .unwrap();
    Ok(())
}

#[ignore]
#[test]
fn test_signing_ecdsa() {
    // Create a key beforehand using the parsec-tool and then run the test.
    let key_name = String::from("PARSEC_TEST_ECDSA_KEY");

    // A 256 bit ECDSA signing operation produces 64 bytes signature
    let mut signature: [u8; 64] = [0; 64];
    let sign_alg = AsymmetricSignature::Ecdsa {
        hash_alg: Hash::Sha256.into(),
    };

    let _ = sign_verify(
        &key_name,
        &mut signature,
        sign_alg,
        PARSEC_PROVIDER_ECDSA_NAME,
    );
}

#[ignore]
#[test]
fn test_signing_rsa() {
    // Create a key beforehand using the parsec-tool and then run the test.
    let key_name = String::from("PARSEC_TEST_RSA_KEY");

    // A 2048 bit RSA signing operation produces 256 bytes signature
    let mut signature: [u8; 256] = [0; 256];
    let sign_alg = AsymmetricSignature::RsaPkcs1v15Sign {
        hash_alg: Hash::Sha256.into(),
    };

    let _ = sign_verify(
        &key_name,
        &mut signature,
        sign_alg,
        PARSEC_PROVIDER_RSA_NAME,
    );
}
