// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Security options like cipher suites, signature algorithms, versions, etc.
//!
//! See <https://aws.github.io/s2n-tls/usage-guide/ch06-security-policies.html>

use crate::error::Error;
use core::fmt;
use std::ffi::{CStr, CString};

#[derive(Clone, PartialEq)]
enum Context {
    Static(&'static [u8]),
    Owned(CString),
}

#[derive(Clone, PartialEq)]
pub struct Policy(Context);

impl Policy {
    pub(crate) fn as_cstr(&self) -> &CStr {
        match &self.0 {
            Context::Static(x) => unsafe {
                // Safety: Policies are always created with null-terminated strings
                CStr::from_bytes_with_nul_unchecked(x)
            },
            Context::Owned(x) => x.as_c_str(),
        }
    }

    /// See the s2n-tls usage guide for details on available policies:
    /// <https://aws.github.io/s2n-tls/usage-guide/ch06-security-policies.html>
    pub fn from_version(version: &str) -> Result<Policy, Error> {
        let cstr = CString::new(version).map_err(|_| Error::INVALID_INPUT)?;
        let context = Context::Owned(cstr);
        Ok(Self(context))
    }
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Policy").field(&self.as_cstr()).finish()
    }
}

macro_rules! policy {
    ($version:expr) => {
        Policy(Context::Static(concat!($version, "\0").as_bytes()))
    };
}

/// Default policy
///
/// # Warning
///
/// Cipher suites, curves, signature algorithms, or other security policy options
/// may be added or removed from "default" in order to keep it up to date with
/// current security best practices.
///
/// That means that updating the library may cause the policy to change. If peers
/// are expected to be reasonably modern and support standard options, then this
/// should not be a problem. But if peers rely on a deprecated option that is removed,
/// they may be unable to connect.
///
/// If you instead need a static, versioned policy, choose one according to the s2n-tls usage guide:
/// <https://aws.github.io/s2n-tls/usage-guide/ch06-security-policies.html>
pub const DEFAULT: Policy = policy!("default");

/// Default policy supporting TLS1.3
///
/// # Warning
///
/// Cipher suites, curves, signature algorithms, or other security policy options
/// may be added or removed from "default_tls13" in order to keep it up to date with
/// current security best practices.
///
/// That means that updating the library may cause the policy to change. If peers
/// are expected to be reasonably modern and support standard options, then this
/// should not be a problem. But if peers rely on a deprecated option that is removed,
/// they may be unable to connect.
///
/// If you instead need a static, versioned policy, choose one according to the s2n-tls usage guide:
/// <https://aws.github.io/s2n-tls/usage-guide/ch06-security-policies.html>
pub const DEFAULT_TLS13: Policy = policy!("default_tls13");

#[cfg(feature = "pq")]
pub const TESTING_PQ: Policy = policy!("PQ-TLS-1-0-2021-05-26");

pub const ALL_POLICIES: &[Policy] = &[
    DEFAULT,
    DEFAULT_TLS13,
    #[cfg(feature = "pq")]
    TESTING_PQ,
];
