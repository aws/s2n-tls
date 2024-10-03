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

    let downloaded_pcaps_path = std::env!("DOWNLOADED_PCAPS_PATH");
    let downloaded_pcaps = pcaps_from(downloaded_pcaps_path);

    local_pcaps.chain(downloaded_pcaps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::*;
    use std::collections::HashSet;

    #[test]
    fn pcaps_source() -> Result<()> {
        let pcaps = all_pcaps();
        println!("All pcaps: ");
        let paths: HashSet<String> = pcaps
            .map(|file_str| {
                println!("{}", file_str);
                let (path, _file) = file_str.rsplit_once("/").expect("No path");
                path.to_owned()
            })
            .collect();
        // If we're also using downloaded pcaps, we'd expected to be reading
        // pcaps from at least two sources (the local data and the downloaded data).
        if cfg!(feature = "download") {
            assert!(paths.len() > 1);
        } else {
            assert!(paths.len() == 1);
        }
        Ok(())
    }
}
