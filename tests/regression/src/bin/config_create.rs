// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Harness to build an empty s2n-tls config object.
//!
//! Empty config creation is implemented seperate from a configured, usable config object.
//! This is to measure the performance of each component seperately.
//!

use crabgrind as cg;
use s2n_tls::config::Builder;

fn main() -> Result<(), s2n_tls::error::Error> {
    
    let builder: Builder = Builder::new();
    
    builder.build()?;

    cg::cachegrind::stop_instrumentation();
    
    Ok(())
}

