// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod harness;
#[cfg(feature = "openssl")]
pub mod openssl;
#[cfg(feature = "rustls")]
pub mod rustls;
pub mod s2n_tls;

#[cfg(feature = "openssl")]
pub use crate::openssl::OpenSslConnection;
#[cfg(feature = "rustls")]
pub use crate::rustls::RustlsConnection;
pub use crate::{
    harness::{
        get_cert_path, CipherSuite, ConnectedBuffer, CryptoConfig, HandshakeType, KXGroup, Mode,
        PemType, SigType, TlsConnPair, TlsConnection,
    },
    s2n_tls::S2NConnection,
};

// controls profiler frequency for flamegraph generation in benchmarks
pub const PROFILER_FREQUENCY: i32 = 100;
