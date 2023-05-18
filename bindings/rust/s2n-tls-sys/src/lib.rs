// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[rustfmt::skip]
mod api;

pub use api::*;

/// conditionally declare the module only if `feature` is enabled. If the
/// feature is enabled, import all symbols into the main namespace.
macro_rules! conditional_module {
    ($mod_name:ident, $feature:literal) => {
        #[cfg(feature = $feature)]
        // bindgen will automatically rustfmt everything, but we use nightly rustfmt as
        // the authoritiative rustfmt so that doesn't work for us
        #[rustfmt::skip]
        mod $mod_name;

        #[cfg(feature = $feature)]
        pub use $mod_name::*;
    };
}

conditional_module!(crl, "crl");
conditional_module!(fingerprint, "fingerprint");
conditional_module!(internal, "internal");
conditional_module!(npn, "npn");
conditional_module!(quic, "quic");
conditional_module!(renegotiate, "renegotiate");

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
#[rustfmt::skip]
mod tests;
