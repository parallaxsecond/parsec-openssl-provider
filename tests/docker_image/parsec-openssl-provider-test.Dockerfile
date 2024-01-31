# Copyright 2023 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0
FROM ubuntu:22.04

RUN apt-get update && apt-get -y upgrade
RUN apt install -y autoconf-archive libcmocka0 libcmocka-dev procps
RUN apt install -y iproute2 build-essential git pkg-config gcc libtool automake libssl-dev uthash-dev doxygen libjson-c-dev
RUN apt install -y --fix-missing wget python3 cmake clang
RUN apt install -y libini-config-dev libcurl4-openssl-dev curl libgcc1
RUN apt install -y python3-distutils libclang-11-dev protobuf-compiler python3-pip
RUN apt install -y libgcrypt20-dev uuid-dev
RUN apt install -y libssl-dev git gcc openssl

# Setup git config
RUN git config --global user.email "some@email.com"
RUN git config --global user.name "Parsec Team"

WORKDIR /tmp

# Install Rust toolchain for all users
# This way of installing allows all users to call the same binaries, but non-root
# users cannot modify the toolchains or install new ones.
# See: https://github.com/rust-lang/rustup/issues/1085
ENV RUSTUP_HOME /opt/rust
ENV CARGO_HOME /opt/rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path
ENV PATH="/root/.cargo/bin:/opt/rust/bin:${PATH}"

# For running tests Parsec is configured with the socket in /tmp/
ENV PARSEC_SERVICE_ENDPOINT="unix:/tmp/parsec.sock"
