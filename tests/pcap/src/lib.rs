// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod client_hello;
pub mod handshake_message;
pub mod packet;

/// Creates an iterator over all test pcap file paths
pub fn all_pcaps() -> impl Iterator<Item = String> {
    std::fs::read_dir("data")
        .expect("Missing test pcap file")
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            path.to_str().map(std::string::ToString::to_string)
        })
}
