// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod harness;
#[cfg(feature = "openssl")]
pub mod openssl;
#[cfg(feature = "openssl")]
pub mod openssl_extension;
#[cfg(feature = "rustls")]
pub mod rustls;
pub mod s2n_tls;
// Although these are integration tests, we deliberately avoid the "integration"
// provided in the default repo setup, because it will run tests in serial rather
// than parallel/
// https://matklad.github.io/2021/02/27/delete-cargo-integration-tests.html
#[cfg(test)]
mod tests;

#[cfg(feature = "openssl")]
pub use crate::openssl::OpenSslConnection;
#[cfg(feature = "rustls")]
pub use crate::rustls::RustlsConnection;
pub use crate::{
    harness::{
        get_cert_path, CipherSuite, CryptoConfig, HandshakeType, KXGroup, Mode, PemType, SigType,
        TlsConnPair, TlsConnection,
    },
    s2n_tls::S2NConnection,
};

// controls profiler frequency for flamegraph generation in benchmarks
pub const PROFILER_FREQUENCY: i32 = 100;
