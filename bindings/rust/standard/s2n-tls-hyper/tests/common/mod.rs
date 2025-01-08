// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{callbacks::VerifyHostNameCallback, config, error::Error, security::DEFAULT_TLS13};

pub mod echo;

/// NOTE: this certificate and key are used for testing purposes only!
pub const CERT_PEM: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../certs/cert.pem"));
pub const KEY_PEM: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../certs/key.pem"));

pub fn config() -> Result<config::Builder, Error> {
    let mut builder = config::Config::builder();
    builder.set_security_policy(&DEFAULT_TLS13)?;
    builder.trust_pem(CERT_PEM)?;
    builder.load_pem(CERT_PEM, KEY_PEM)?;
    Ok(builder)
}

pub struct InsecureAcceptAllCertificatesHandler {}
impl VerifyHostNameCallback for InsecureAcceptAllCertificatesHandler {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}
