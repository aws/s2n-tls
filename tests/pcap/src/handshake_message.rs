// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use rtshark::RTSharkBuilder;
use std::collections::HashMap;

use crate::packet::Packet;
use crate::packet::PacketId;
use crate::packet::PacketIterator;

/// TLS handshake message type, as defined in the TLS RFC.
///
/// See https://datatracker.ietf.org/doc/html/rfc8446#section-4
pub type MessageType = u8;

/// A TLS handshake message, as defined in the TLS RFC.
///
/// See https://datatracker.ietf.org/doc/html/rfc8446#section-4
#[derive(Debug, Clone, Default)]
pub struct HandshakeMessage {
    /// TLS handshake message type, as defined in the TLS RFC.
    ///
    /// See https://datatracker.ietf.org/doc/html/rfc8446#section-4
    pub message_type: MessageType,

    /// Packet containing handshake message metadata.
    pub packet: Packet,

    /// List of TLS records containing the TLS handshake message.
    ///
    /// TLS handshake messages can be fragmented across multiple TLS records.
    /// Each record is represented as a Vec<u8>, and includes the record header.
    ///
    /// See https://datatracker.ietf.org/doc/html/rfc8446#section-5
    pub records: Vec<Vec<u8>>,
}

impl HandshakeMessage {
    const FRAGMENT: &'static str = "tls.handshake.fragment";
    const FRAGMENTS_COUNT: &'static str = "tls.handshake.fragment.count";

    /// Returns the complete handshake message in bytes.
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for record in &self.records {
            // Each record starts with a 5-byte header.
            // To join the record payloads into a complete valid message,
            // we have to strip off those headers first.
            bytes.extend_from_slice(&record[5..])
        }
        bytes
    }

    fn parse_fields(packet: Packet, tcp_packets: &HashMap<PacketId, Packet>) -> Result<Self> {
        let message_type = packet
            .metadata(Builder::MESSAGE_TYPE)
            .context("Missing handshake message type")?
            .parse::<u8>()?;

        // TLS handshake messages may be fragmented across multiple TLS records.
        // tshark only associates the handshake message metadata with the final record,
        // but we must retrieve all the records to fully capture the raw message bytes.
        //
        // 'fragment_ids' here is a list of the packets containing
        // TLS records which contain fragments of this handshake message.
        //
        // The "tls.handshake.fragment" data from tshark actually includes the
        // full hex of each fragment, not just the id of each packet. But rtshark
        // uses the `show` tag instead of the `value` tag, and the `show` tag is
        // just the packet id. There's currently no way to access the `value` tag.
        let fragment_ids = packet.all_metadata(Self::FRAGMENT);
        let fragment_ids = if fragment_ids.is_empty() {
            vec![packet.id()]
        } else {
            fragment_ids
                .into_iter()
                .map(|s| s.parse::<PacketId>().context("Bad fragment id"))
                .collect::<Result<Vec<_>>>()?
        };

        // For each fragment, we must retrieve the associated packet.
        // The TLS record is the TCP payload of that packet.
        let mut records = Vec::new();
        for fragment_id in fragment_ids {
            let fragment = tcp_packets
                .get(&fragment_id)
                .context("Missing handshake message fragment record")?;
            let tcp_payload = fragment
                .metadata(Builder::TCP_PAYLOAD)
                .context("Missing handshake message tcp payload")?;
            // The TCP payload is a hex string. However, rtshark formats hex strings
            // like "AB:CD:EF:12" instead of "ABCDEF12".
            let hex = tcp_payload.replace(':', "");
            let bytes = hex::decode(hex)?;
            records.push(bytes);
        }

        let count = packet
            .metadata(Self::FRAGMENTS_COUNT)
            .unwrap_or("1")
            .parse::<usize>()?;
        if count != records.len() {
            bail!("Unable to find all tls records for tls message")
        }

        Ok(Self {
            message_type,
            packet,
            records,
        })
    }

    fn from_packet(packet: Packet, tcp_packets: &HashMap<PacketId, Packet>) -> Result<Self> {
        let packet_id = packet.id();
        Self::parse_fields(packet, tcp_packets)
            .with_context(|| format!("Failed to parse frame {}", packet_id))
    }

    pub fn builder() -> Builder {
        Builder::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Builder {
    message_type: Option<u8>,
    capture_file: Option<String>,
}

impl Builder {
    // "tcp.payload" is actually insufficient. It's uncommon,
    // but a TLS record can be split across multiple TCP segments.
    // Then we would also need to check for "tcp.reassembled.data".
    // However, rtshark currently doesn't support that field:
    // https://github.com/CrabeDeFrance/rtshark/pull/16
    //
    // For now, parsing will fail if TLS records are reassembled.
    const TCP_PAYLOAD: &'static str = "tcp.payload";

    const MESSAGE_TYPE: &'static str = "tls.handshake.type";

    pub(crate) fn set_type(&mut self, message_type: u8) -> &mut Self {
        self.message_type = Some(message_type);
        self
    }

    pub fn set_capture_file(&mut self, file: &str) -> &mut Self {
        self.capture_file = Some(file.to_string());
        self
    }

    fn build_from_capture(
        self,
        capture: rtshark::RTSharkBuilderReady,
    ) -> Result<Vec<HandshakeMessage>> {
        // We are either looking for a specific type of TLS handshake message,
        // or all TLS handshake messages.
        let filter = if let Some(message_type) = self.message_type {
            format!("{} == {}", Self::MESSAGE_TYPE, message_type)
        } else {
            Self::MESSAGE_TYPE.to_string()
        };

        // tshark associates a LOT of metadata with each packet. Filtering that
        // metadata (like by using `metadata_whitelist`) significantly improves
        // both performance and memory usage.
        //
        // We potentially need all available metadata for the TLS handshake
        // messages that we're interested in, but we only need the TCP payloads
        // for any packets that don't contain TLS handshake messages.
        let message_capture = capture.display_filter(&filter).spawn()?;
        let tcp_capture = capture
            .display_filter(Self::TCP_PAYLOAD)
            .metadata_whitelist(Self::TCP_PAYLOAD)
            .metadata_whitelist(Packet::PACKET_ID)
            .spawn()?;

        let tcp_packets = PacketIterator(tcp_capture).into_lookup();
        let messages = PacketIterator(message_capture)
            .map(|packet| HandshakeMessage::from_packet(packet, &tcp_packets))
            .collect::<Result<Vec<_>>>()?;
        Ok(messages)
    }

    pub(crate) fn build(mut self) -> Result<Vec<HandshakeMessage>> {
        let file = self
            .capture_file
            .take()
            .context("No capture file provided")?;
        let capture = RTSharkBuilder::builder().input_path(&file);
        self.build_from_capture(capture)
            .with_context(|| format!("Failed to parse capture file {}", &file))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmentation() -> Result<()> {
        let mut builder = Builder::default();
        builder.set_capture_file("data/fragmented_ch.pcap");
        let messages = builder.build()?;

        let first = messages.first().unwrap();
        assert_eq!(first.records.len(), 3);
        let bytes = first.bytes();
        // Correct length read from wireshark
        assert_eq!(bytes.len(), 16262);

        Ok(())
    }

    #[test]
    fn multiple_handshakes() -> Result<()> {
        let mut builder = Builder::default();
        builder.set_capture_file("data/multiple_hellos.pcap");
        let messages = builder.build()?;

        // Only one ServerHello can appear per handshake, so count the number
        // of ServerHello messages to count the number of handshakes.
        let server_hello_type = 2;
        let count = messages
            .iter()
            .filter(|m| m.message_type == server_hello_type)
            .count();
        assert_eq!(count, 5);
        Ok(())
    }

    #[test]
    fn from_pcaps() -> Result<()> {
        let pcaps = crate::all_pcaps();

        for pcap in pcaps {
            let pcap: String = pcap;

            let mut builder = Builder::default();
            builder.set_capture_file(&pcap);
            let messages = builder.build().unwrap();
            assert!(!messages.is_empty())
        }

        Ok(())
    }
}
