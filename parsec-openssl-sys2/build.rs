// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::env;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

const MINIMUM_VERSION: &str = "3.0.0";

fn main() -> std::io::Result<()> {
    // Use package config to ensure openssl version 3.0.0 or higher is installed
    let openssl = pkg_config::Config::new()
        .atleast_version(MINIMUM_VERSION)
        .probe("openssl")
        .expect("Failed to find openssl version above 3.0.0");

    // The include path points to the openssl development headers installed by libss-dev
    let openssl_include_path = openssl.include_paths[0]
        .clone()
        .into_os_string()
        .into_string()
        .expect("Error converting OsString to String.");

    // Generate bindings for the required headers
    let openssl_builder = bindgen::Builder::default()
        .header(format!("{}/openssl/core_dispatch.h", openssl_include_path))
        .header(format!("{}/openssl/types.h", openssl_include_path))
        .header(format!("{}/openssl/params.h", openssl_include_path))
        .header(format!("{}/openssl/core_names.h", openssl_include_path))
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
