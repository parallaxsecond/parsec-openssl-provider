// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

// Parameter names that Providers can define
pub const OSSL_PROV_PARAM_NAME: &[u8; 5] = b"name\0";
pub const OSSL_PROV_PARAM_VERSION: &[u8; 8] = b"version\0";
pub const OSSL_PROV_PARAM_BUILDINFO: &[u8; 10] = b"buildinfo\0";
pub const OSSL_PROV_PARAM_STATUS: &[u8; 7] = b"status\0";
