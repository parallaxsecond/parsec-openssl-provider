// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use e2e_tests::*;
use parsec_openssl_provider::parsec_openssl2::openssl_returns_nonnull;

#[ignore]
#[test]
fn test_store_for_key() {
    let provider_path = String::from("../../target/debug/");
    let provider_name = String::from("libparsec_openssl_provider_shared");

    let lib_ctx: LibCtx = LibCtx::new().unwrap();
    let _provider: Provider = load_provider(&lib_ctx, &provider_name, provider_path);

    // Create a key beforehand using the parsec-tool and then run the test.
    let key_name: &[u8; 8] = b"parsec:\0";

    unsafe {
        let ctx = openssl_returns_nonnull(OSSL_STORE_open(
            key_name.as_ptr() as _,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            None,
            std::ptr::null_mut(),
        ))
        .unwrap();
        /*
         * OSSL_STORE_eof() simulates file semantics for any repository to signal
         * that no more data can be expected
         */
        assert_ne!(OSSL_STORE_eof(ctx), 1);
        while OSSL_STORE_eof(ctx) != 1 {
            let info = OSSL_STORE_load(ctx);
            assert_ne!(info, std::ptr::null_mut());
            /*
             * Do whatever is necessary with the OSSL_STORE_INFO,
             * here just one example
             */

            /*
               switch (OSSL_STORE_INFO_get_type(info)) {
               case OSSL_STORE_INFO_CERT:
                   /* Print the X.509 certificate text */
                   X509_print_fp(stdout, OSSL_STORE_INFO_get0_CERT(info));
                   /* Print the X.509 certificate PEM output */
                   PEM_write_X509(stdout, OSSL_STORE_INFO_get0_CERT(info));
                   break;
               }
            */
        }
        OSSL_STORE_close(ctx);
    }
}
