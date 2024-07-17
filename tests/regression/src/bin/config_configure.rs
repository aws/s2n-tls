// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Harness to build a configured s2n-tls config object.
//!
//! This harness only measures the cost of setting the security policy and host callback verification.
//! Loading and trusting certs is typically also included in this step but for a more fine-grain
//! performance analysis, it is left out so cert creation can be measured in its own harness
//!

use crabgrind as cg;
use s2n_tls::{security, config::Builder};
use regression::InsecureAcceptAllCertificatesHandler;

fn main() -> Result<(), s2n_tls::error::Error> {
    cg::cachegrind::stop_instrumentation();
    
    let mut builder = Builder::new();
    
    cg::cachegrind::start_instrumentation();

    builder
        .set_security_policy(&security::DEFAULT_TLS13)
        .expect("Unable to set config cipher preferences");
    builder
        .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
        .expect("Unable to set a host verify callback.");
    let _config = builder.build().expect("Failed to build config");

    cg::cachegrind::stop_instrumentation();
    
    Ok(())
}
