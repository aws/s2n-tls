// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod harness;
pub mod rustls;
pub mod s2n_tls;
pub use crate::{
    harness::{CipherSuite, CryptoConfig, ECGroup, TlsBenchHarness},
    rustls::RustlsHarness,
    s2n_tls::S2NHarness,
};

const SERVER_KEY_PATH: &str = "certs/server-key.pem";
const SERVER_CERT_CHAIN_PATH: &str = "certs/fullchain.pem";
const CA_CERT_PATH: &str = "certs/ca-cert.pem";

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn cert_paths_valid() {
        assert!(Path::new(crate::SERVER_KEY_PATH).exists());
        assert!(Path::new(crate::SERVER_CERT_CHAIN_PATH).exists());
        assert!(Path::new(crate::CA_CERT_PATH).exists());
    }
}
