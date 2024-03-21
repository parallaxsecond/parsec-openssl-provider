// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::openssl_binding::OSSL_ALGORITHM;
use parsec_openssl2::*;

pub const PARSEC_PROVIDER_SIGNATURE: [OSSL_ALGORITHM; 1] = [ossl_algorithm!()];
