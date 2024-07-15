// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{callbacks::VerifyHostNameCallback, config::Builder, security};
type Error = Box<dyn std::error::Error>;

//Initializes an empty config object without paramter setting
pub fn create_empty_config() -> Result<s2n_tls::config::Builder, Error> {
    Ok(Builder::new())
}

pub struct InsecureAcceptAllCertificatesHandler {}

impl VerifyHostNameCallback for InsecureAcceptAllCertificatesHandler {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}


// Configure the security policy and host call back verification for an s2n_tls config
pub fn configure_config(
    mut builder: s2n_tls::config::Builder,
    cipher_prefs: &security::Policy
) -> Result<s2n_tls::config::Builder, Error> {
    builder
        .set_security_policy(cipher_prefs)
        .expect("Unable to set config cipher preferences");
    builder
        .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
        .expect("Unable to set a host verify callback.");
    Ok(builder)
}