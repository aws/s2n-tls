// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use aws_kms_tls_auth::DecodeValue;
use aws_kms_tls_auth::PresharedKeyClientHello;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = PresharedKeyClientHello::decode_from(data);
});
