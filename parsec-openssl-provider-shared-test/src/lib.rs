// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::missing_safety_doc)]

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(improper_ctypes)]
// These are test bindings generated from the "evp.h" and "provider.h" header files which
// provide interfaces for openssl clients.
pub mod openssl_test_bindings {
    include!(concat!(env!("OUT_DIR"), "/openssl_test_bindings.rs"));
}

