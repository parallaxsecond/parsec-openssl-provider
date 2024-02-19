#!/usr/bin/env bash

# Copyright 2023 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -ex

echo "OpenSSL version being used:"
openssl version

# Build parsec provider shared library
pushd parsec-openssl-provider-shared/ &&
cargo build
popd

# Try loading the build parsec provider 
provider_load_result=$(openssl list -providers -provider-path ./target/debug/ -provider libparsec_openssl_provider_shared)
echo $provider_load_result

test_string='Providers:
  libparsec_openssl_provider_shared
    name: Parsec OpenSSL Provider
    version: 0.1.0
    status: active'

if [[ $test_string == $provider_load_result ]]; then
    echo "Parsec OpenSSL Provider loaded successfully!!!!"
    exit 0;
fi

echo "Loaded Provider has unexpected parameters!!!!"
exit 1
