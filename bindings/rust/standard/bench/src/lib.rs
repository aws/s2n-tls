// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod harness;
pub mod openssl;
pub mod rustls;
pub mod s2n_tls;

pub use crate::{
    harness::{
        get_cert_path, CipherSuite, CryptoConfig, HandshakeType, KXGroup, Mode, PemType, SigType,
        TlsConnPair, TlsConnection,
    },
    openssl::OpenSslConnection,
    rustls::RustlsConnection,
    s2n_tls::S2NConnection,
};

// controls profiler frequency for flamegraph generation in benchmarks
pub const PROFILER_FREQUENCY: i32 = 100;
