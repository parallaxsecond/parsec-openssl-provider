// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#![allow(non_camel_case_types)]

pub mod param;

pub mod openssl_binding {
    include!(concat!(env!("OUT_DIR"), "/openssl_bindings.rs"));
}
