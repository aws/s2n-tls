// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use kms_tls_psk::DecodeValue;
use kms_tls_psk::PresharedKeyClientHello;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = PresharedKeyClientHello::decode_from(data);
});
