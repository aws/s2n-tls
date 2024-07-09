// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use rtshark::Metadata;
use std::collections::HashMap;

/// According to the Wireshark docs, the frame number (frame.number)
/// is an unsigned 32-bit integer.
/// See https://www.wireshark.org/docs/dfref/f/frame.html.
pub(crate) type PacketId = u32;

#[derive(Debug, Clone, Default)]
pub struct Packet(rtshark::Packet);

/// rtshark represents entries / elements in a capture as "packets".
///
/// rtshark packets can be thought of as equivalent to Wireshark "frames".
/// From https://wiki.wireshark.org/Protocols/frame:
/// > The frame protocol isn't a real protocol itself, but used by Wireshark
/// > as a base for all the protocols on top of it.
impl Packet {
    /// The frame number uniquely identifies a frame / packet.
    pub(crate) const PACKET_ID: &'static str = "frame.number";

    pub fn id(&self) -> PacketId {
        self.metadata(Self::PACKET_ID)
            .expect("Packet missing id / frame number")
            .parse::<PacketId>()
            .expect("Packet id / frame number invalid")
    }

    /// Retrieve packet metadata by key.
    ///
    /// Some metadata keys are associated with multiple values. In that case,
    /// `all_metadata` should be called instead of `metadata`.
    ///
    /// Metadata keys are equivalent to Wireshark filters.
    /// TLS values: https://www.wireshark.org/docs/dfref/t/tls.html
    /// TCP values: https://www.wireshark.org/docs/dfref/t/tcp.html
    pub(crate) fn metadata(&self, key: &str) -> Option<&str> {
        let (layer_name, _) = key.split_once('.').expect("key is layer");
        self.0
            .layer_name(layer_name)
            .and_then(|layer| layer.metadata(key))
            .map(Metadata::value)
    }

    /// Retrieve a list of packet metadata by key.
    ///
    /// Metadata is equivalent to Wireshark filters.
    /// TLS values: https://www.wireshark.org/docs/dfref/t/tls.html
    /// TCP values: https://www.wireshark.org/docs/dfref/t/tcp.html
    pub(crate) fn all_metadata(&self, key: &str) -> Vec<&str> {
        let (layer_name, _) = key.split_once('.').expect("key is layer");
        if let Some(layer) = self.0.layer_name(layer_name) {
            layer
                .iter()
                .filter(|metadata| metadata.name() == key)
                .map(Metadata::value)
                .collect()
        } else {
            Vec::new()
        }
    }
}

pub(crate) struct PacketIterator(pub(crate) rtshark::RTShark);
impl Iterator for PacketIterator {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.0.read().expect("Failed to read from tshark");
        packet.map(Packet)
    }
}

impl PacketIterator {
    pub(crate) fn into_lookup(self) -> HashMap<PacketId, Packet> {
        self.map(|packet| (packet.id(), packet)).collect()
    }
}
