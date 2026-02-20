// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module holds items that make it simpler to write our tests.
//!
//! This module should never hold any tests of TLS implementations.

use s2n_tls::callbacks::VerifyHostNameCallback;

pub mod capability_check;
pub mod certs;

pub struct IgnoreHostName;
impl VerifyHostNameCallback for IgnoreHostName {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}
