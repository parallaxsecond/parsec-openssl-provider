#!/usr/bin/env bash

# Copyright 2023 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -ex

usage () {
    printf "
Continuous Integration test script

Usage: ./ci.sh --TEST --OPTION
where TEST can be one of:
    --build
    --build-and-test
    --static-checks
and OPTION one of:
    --create-keys
"
}

wait_for_service() {
    while [ -z "$(pgrep parsec)" ]; do
        sleep 1
    done

    sleep 5

    # Check that Parsec successfully started and is running
    pgrep parsec >/dev/null
}

error_msg () {
    echo "Error: $1"
    usage
    exit 1
}

# Change rust toolchain version
if [[ ! -z ${RUST_TOOLCHAIN_VERSION:+x} ]]; then
	rustup override set ${RUST_TOOLCHAIN_VERSION}
fi

BUILD="False"
TEST="False"
STATIC_CHECKS="False"
CREATE_KEYS="False"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --build )
            BUILD="True"
        ;;
        --build-and-test )
            BUILD="True"
            TEST="True"
        ;;
        --static-checks )
            STATIC_CHECKS="True"
        ;;
        --create-keys )
            CREATE_KEYS="True"
        ;;
        *)
            error_msg "Unknown argument: $1"
        ;;
    esac
    shift
done

rustup update

if [ "$BUILD" == "True" ]; then
    echo "OpenSSL version being used:"
    openssl version

    # Build parsec provider shared library
    pushd parsec-openssl-provider-shared/ &&
    cargo build
    popd
fi

if [ "$TEST" == "True" ]; then
    pushd /tmp/parsec
    ./target/debug/parsec -c e2e_tests/provider_cfg/mbed-crypto/config.toml &
    popd

    wait_for_service

    if [ "$CREATE_KEYS" == "True" ]; then
        parsec-tool create-rsa-key -s -b 2048 -k PARSEC_TEST_KEYNAME
    fi
    # Try loading the build parsec provider 
    PROVIDER_LOAD_RESULT=$(openssl list -providers -provider-path ./target/debug/ -provider libparsec_openssl_provider_shared)
    echo $PROVIDER_LOAD_RESULT

    TEST_STRING='Providers:
  libparsec_openssl_provider_shared
    name: Parsec OpenSSL Provider
    version: 0.1.0
    status: active'

    if [[ $TEST_STRING != $PROVIDER_LOAD_RESULT ]]; then
        echo "Loaded Provider has unexpected parameters!!!!"
        exit 1
    fi

    echo "Parsec OpenSSL Provider loaded successfully!!!!"

    pushd parsec-openssl-provider
    cargo test
    popd

    # The parsec-openssl-provider-shared/e2e_tests/src/lib.rs contains some unit tests from the generated
    # test bindings from bindgen. So run only the integration tests in the test crate. 
    pushd parsec-openssl-provider-shared/e2e_tests/
    cargo test --test '*' -- --nocapture
    popd
fi

if [ "$STATIC_CHECKS" == "True" ]; then
    if cargo fmt --version; then
        cargo fmt --all -- --check
    fi

    if cargo clippy --version; then
        cargo clippy --all-targets -- -D clippy::all -D clippy::cargo
    fi
fi
