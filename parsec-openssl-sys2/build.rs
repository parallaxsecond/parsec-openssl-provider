// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::env;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let openssl_builder = bindgen::Builder::default()
        .header("src/c/openssl.h")
        .generate_comments(false)
        .size_t_is_usize(true);

    // Build the bindings
    let openssl_bindings = openssl_builder
        .generate()
        .map_err(|_| Error::new(ErrorKind::Other, "Unable to generate bindings to openssl"))?;

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    openssl_bindings.write_to_file(out_path.join("openssl_bindings.rs"))?;

    Ok(())
}
