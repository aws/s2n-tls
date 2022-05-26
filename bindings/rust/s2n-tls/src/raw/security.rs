// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::fmt;
use std::ffi::CStr;

#[derive(Clone, PartialEq)]
pub struct Policy(&'static [u8]);

impl Policy {
    pub(crate) fn as_cstr(&self) -> &CStr {
        unsafe {
            // Safety: Policies are always created with null-terminated strings
            CStr::from_bytes_with_nul_unchecked(self.0)
        }
    }
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Policy").field(&self.as_cstr()).finish()
    }
}

macro_rules! policy {
    ($name:ident, $version:expr) => {
        pub const $name: Policy = Policy(concat!($version, "\0").as_bytes());
    };
}

policy!(DEFAULT, "default");
policy!(DEFAULT_TLS13, "default_tls13");

#[cfg(feature = "pq")]
policy!(TESTING_PQ, "PQ-TLS-1-0-2021-05-26");

pub const ALL_POLICIES: &[Policy] = &[
    DEFAULT,
    DEFAULT_TLS13,
    #[cfg(feature = "pq")]
    TESTING_PQ,
];
