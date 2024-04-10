// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(improper_ctypes)]
pub mod openssl_bindings {
    include!(concat!(env!("OUT_DIR"), "/openssl_bindings.rs"));
}
