// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod api;

pub use api::*;

#[cfg(feature = "quic")]
mod quic;

#[cfg(feature = "quic")]
pub use quic::*;

// Additional defines that don't get imported with bindgen

pub mod s2n_status_code {
    pub type Type = libc::c_int;
    pub const SUCCESS: Type = 0;
    pub const FAILURE: Type = -1;
}

pub mod s2n_tls_version {
    pub type Type = libc::c_int;
    pub const SSLV2: Type = 20;
    pub const SSLV3: Type = 30;
    pub const TLS10: Type = 31;
    pub const TLS11: Type = 32;
    pub const TLS12: Type = 33;
    pub const TLS13: Type = 34;
    pub const UNKNOWN: Type = 0;
}

#[cfg(test)]
mod tests;
