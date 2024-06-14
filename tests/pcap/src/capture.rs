// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use rtshark::Metadata;
use rtshark::Packet;
use rtshark::RTShark;

pub(crate) fn read_all(mut tshark: RTShark) -> Vec<Packet> {
    let mut packets = Vec::new();
    while let Ok(Some(packet)) = tshark.read() {
        packets.push(packet)
    }
    packets
}

pub(crate) fn get_metadata<'a>(packet: &'a Packet, key: &'a str) -> Option<&'a str> {
    let (layer_name, _) = key.split_once('.').expect("key is layer");
    packet
        .layer_name(layer_name)
        .and_then(|layer| layer.metadata(key))
        .map(Metadata::value)
}

pub(crate) fn get_all_metadata<'a>(packet: &'a Packet, key: &'a str) -> Vec<&'a str> {
    let (layer_name, _) = key.split_once('.').expect("key is layer");
    if let Some(layer) = packet.layer_name(layer_name) {
        layer
            .iter()
            .filter(|metadata| metadata.name() == key)
            .map(Metadata::value)
            .collect()
    } else {
        Vec::new()
    }
}

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
