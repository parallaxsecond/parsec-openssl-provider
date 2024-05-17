// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use e2e_tests::*;
use openssl::md::Md;
use openssl::md_ctx::MdCtx;
use openssl::pkey::Private;
use parsec_client::core::basic_client::BasicClient;
use parsec_client::core::interface::operations::psa_algorithm::{AsymmetricSignature, Hash};
use parsec_client::core::interface::operations::{
    psa_hash_compare, psa_hash_compute, psa_sign_hash,
};
use parsec_openssl_provider::parsec_openssl2::ossl_param;
use parsec_openssl_provider::parsec_openssl2::{openssl_returns_1, Openssl2Error};
use parsec_openssl_provider::signature::EccSignature;
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
    let provider_path = String::from("../../target/debug/");
    let provider_name = String::from("libparsec_openssl_provider_shared");

    let lib_ctx: LibCtx = LibCtx::new().unwrap();
    let _provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

    let mut param = ossl_param!(PARSEC_PROVIDER_KEY_NAME, OSSL_PARAM_UTF8_PTR, key_name);

    let test_string: &[u8; 23] = b"Parsec OpenSSL Provider";
    unsafe {
        let mut parsec_pkey: *mut EVP_PKEY = std::ptr::null_mut();
        load_key(&lib_ctx, &mut param, &mut parsec_pkey, key_type);

        let evp_ctx: *mut EVP_PKEY_CTX = EVP_PKEY_CTX_new_from_pkey(
            lib_ctx.as_ptr() as *mut ossl_lib_ctx_st,
            parsec_pkey,
            PARSEC_PROVIDER_DFLT_PROPERTIES.as_ptr() as *const ::std::os::raw::c_char,
        );

        let mut mdctx = MdCtx::new().unwrap();
        let md = Md::fetch(None, "SHA256", None).unwrap();
        let pkey: openssl::pkey::PKey<Private> = openssl::pkey::PKey::from_ptr(parsec_pkey as _);
        mdctx.digest_sign_init(Some(&md), &pkey).unwrap();

        mdctx.digest_sign(test_string, Some(signature)).unwrap();

        EVP_PKEY_free(parsec_pkey);
    }

    let client = BasicClient::new(Some(String::from("parsec-tool"))).unwrap();

    let hash = client.psa_hash_compute(Hash::Sha256, test_string).unwrap();

    if sign_algorithm.is_ecc_alg() {
        let deserialized: EccSignature = picky_asn1_der::from_bytes(signature).unwrap();
        let mut sign_res_a = deserialized.r.as_unsigned_bytes_be().to_vec();
        let sign_res_b = deserialized.s.as_unsigned_bytes_be().to_vec();
        sign_res_a.extend(sign_res_b);
        client
            .psa_verify_hash(
                key_name,
                hash.as_slice(),
                sign_algorithm,
                sign_res_a.as_slice(),
            )
            .unwrap();
    } else {
        client
            .psa_verify_hash(key_name, hash.as_slice(), sign_algorithm, signature)
            .unwrap();
    }
    Ok(())
}

#[test]
fn test_signing_ecdsa() {
    // Create a key beforehand using the parsec-tool and then run the test.
    let key_name = String::from("PARSEC_TEST_ECDSA_KEY");

    // A 256 bit ECDSA signing operation produces 64 bytes signature
    let mut signature: [u8; 128] = [0; 128];
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

#[test]
fn test_signing_rsa() {
    // Create a key beforehand using the parsec-tool and then run the test.
    let key_name = String::from("PARSEC_TEST_RSA_KEY");

    // A 2048 bit RSA signing operation produces 256 bytes signature
    let mut signature: [u8; 256] = [0; 256];
    let sign_alg = AsymmetricSignature::RsaPss {
        hash_alg: Hash::Sha256.into(),
    };

    let _ = sign_verify(
        &key_name,
        &mut signature,
        sign_alg,
        PARSEC_PROVIDER_RSA_NAME,
    );
}
