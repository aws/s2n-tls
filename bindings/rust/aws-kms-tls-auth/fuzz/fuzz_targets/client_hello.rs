// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use aws_kms_tls_auth::ClientHello;
use aws_kms_tls_auth::DecodeValue;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ClientHello::decode_from(data);
});
