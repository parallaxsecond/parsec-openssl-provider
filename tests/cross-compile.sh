#!/usr/bin/env bash

# Copyright 2024 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

set -xeuf -o pipefail

# Allow the `pkg-config` crate to cross-compile
export PKG_CONFIG_ALLOW_CROSS=1
# Make the `pkg-config` crate use our wrapper
export PKG_CONFIG=/tmp/parsec-openssl-provider/tests/pkg-config

export SYSROOT=/tmp/aarch64-linux-gnu
export RUSTFLAGS="-lcrypto -L/tmp/aarch64-linux-gnu/lib"
cd /tmp/parsec-openssl-provider
cargo build --target aarch64-unknown-linux-gnu \
	--config 'target.aarch64-unknown-linux-gnu.linker="aarch64-linux-gnu-gcc"'

cd parsec-openssl-provider-shared
cargo build --target aarch64-unknown-linux-gnu \
	--config 'target.aarch64-unknown-linux-gnu.linker="aarch64-linux-gnu-gcc"'
