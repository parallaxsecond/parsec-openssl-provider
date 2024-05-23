# Copyright 2024 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0
FROM ubuntu:22.04

RUN apt update && apt-get -y upgrade
RUN apt install -y autoconf-archive libcmocka0 libcmocka-dev procps
RUN apt install -y iproute2 build-essential git pkg-config gcc libtool automake libssl-dev uthash-dev doxygen libjson-c-dev
RUN apt install -y --fix-missing wget python3 cmake clang
RUN apt install -y libini-config-dev curl libgcc1
RUN apt install -y python3-distutils libclang-11-dev protobuf-compiler python3-pip
RUN apt install -y libgcrypt20-dev uuid-dev
RUN apt install -y git gcc


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

# Install aarch64-none-linux-gnu cross compilation toolchain
RUN wget https://developer.arm.com/-/media/Files/downloads/gnu-a/9.2-2019.12/binrel/gcc-arm-9.2-2019.12-x86_64-aarch64-none-linux-gnu.tar.xz?revision=61c3be5d-5175-4db6-9030-b565aae9f766 -O aarch64-gcc.tar.xz
RUN tar --strip-components=1 -C /usr/ -xvf aarch64-gcc.tar.xz
RUN rm aarch64-gcc.tar.xz

# Install cross-compilers
RUN apt install -y gcc-multilib
RUN apt install -y gcc-arm-linux-gnueabihf
RUN apt install -y gcc-aarch64-linux-gnu

WORKDIR /tmp

# Copy OpenSSL cross-compilation script
COPY cross-compile-openssl.sh /tmp/
# Cross-compile OpenSSL for Linux on aarch64
RUN ./cross-compile-openssl.sh aarch64-linux-gnu linux-generic64
