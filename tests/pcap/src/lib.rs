// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod client_hello;
pub mod handshake_message;
pub mod packet;

use std::path::Path;

fn pcaps_from<P: AsRef<Path>>(path: P) -> impl Iterator<Item = String> {
    std::fs::read_dir(path.as_ref())
        .unwrap_or_else(|_| panic!("Unable to read pcap folder: {}", path.as_ref().display()))
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            path.to_str().map(std::string::ToString::to_string)
        })
}

/// Creates an iterator over all test pcap file paths
pub fn all_pcaps() -> impl Iterator<Item = String> {
    let local_pcaps = pcaps_from("data");

    let downloaded_pcaps_path =
        std::env::var("DOWNLOADED_PCAPS_PATH").expect("DOWNLOADED_PCAPS_PATH not set by build.rs");
    let downloaded_pcaps = pcaps_from(downloaded_pcaps_path);

    local_pcaps.chain(downloaded_pcaps)
}
