// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Harness to build an empty s2n-tls config object.
//!
//! Empty config creation is implemented seperate from a configured, usable config object.
//! This is to measure the performance of each component seperately.
//!

use crabgrind as cg;
use regression::create_empty_config;
use s2n_tls::config::Builder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    let builder: Builder = create_empty_config()?;
    
    builder.build().map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    cg::cachegrind::stop_instrumentation();
    
    Ok(())
}

