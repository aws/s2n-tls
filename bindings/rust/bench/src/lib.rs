// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod harness;
pub mod openssl;
pub mod rustls;
pub mod s2n_tls;
pub use crate::{
    harness::{CipherSuite, CryptoConfig, ECGroup, HandshakeType, Mode, TlsBenchHarness},
    openssl::OpenSslHarness,
    rustls::RustlsHarness,
    s2n_tls::S2NHarness,
};

const SERVER_KEY_PATH: &str = "certs/server-key.pem";
const SERVER_CERT_CHAIN_PATH: &str = "certs/server-fullchain.pem";
const CLIENT_KEY_PATH: &str = "certs/client-key.pem";
const CLIENT_CERT_CHAIN_PATH: &str = "certs/client-fullchain.pem";
const CA_CERT_PATH: &str = "certs/ca-cert.pem";

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn cert_paths_valid() {
        assert!(Path::new(crate::SERVER_KEY_PATH).exists());
        assert!(Path::new(crate::SERVER_CERT_CHAIN_PATH).exists());
        assert!(Path::new(crate::CLIENT_KEY_PATH).exists());
        assert!(Path::new(crate::CLIENT_CERT_CHAIN_PATH).exists());
        assert!(Path::new(crate::CA_CERT_PATH).exists());
    }
}
