// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // parse must never panic, regardless of input
    let _ = s2n_tls_metrics_subscriber::parsing::cert::parse(data);
});
