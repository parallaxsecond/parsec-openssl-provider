#!/usr/bin/env bash

# Copyright 2024 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Cross compile the OpenSSL library for a given target

set -xeuf -o pipefail

rustup target add aarch64-unknown-linux-gnu

OPENSSL_VERSION="openssl-3.0.2"
git clone https://github.com/openssl/openssl.git --branch $OPENSSL_VERSION

# Prepare directory for cross-compiled OpenSSL files
mkdir -p /tmp/$1
export INSTALL_DIR=/tmp/$1

pushd /tmp/openssl
# Compile and copy files over
./Configure $2 shared --prefix=$INSTALL_DIR --openssldir=$INSTALL_DIR/openssl --cross-compile-prefix=$1-
make clean
make depend
make -j$(nproc)
make install
popd

unset INSTALL_DIR

pushd /usr/include/openssl
ln -s /tmp/$1/include/openssl/opensslconf.h .
ln -s /tmp/$1/include/openssl/configuration.h .
popd
