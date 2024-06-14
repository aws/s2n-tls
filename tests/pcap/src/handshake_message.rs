// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use rtshark::Packet;
use rtshark::RTSharkBuilder;
use std::collections::HashSet;

use crate::capture::*;

#[derive(Debug, Clone, Default)]
pub struct Message {
    /// TLS handshake message type
    pub message_type: u8,
    /// Packet containing handshake message metadata
    pub packet: Packet,
    /// Ordered TCP payloads as hex encoded strings
    pub payloads: Vec<String>,
    /// Id / number of the TCP frame containing handshake message metadata
    pub frame_num: String,
}

impl Message {
    const FRAGMENT: &'static str = "tls.handshake.fragment";
    const FRAGMENTS_COUNT: &'static str = "tls.handshake.fragment.count";

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for payload in &self.payloads {
            bytes.extend(&hex::decode(&payload)?[5..]);
        }
        Ok(bytes)
    }

    fn from_packet(packet: Packet, frame_num: String, tcp_payloads: &Vec<Packet>) -> Result<Self> {
        let message_type = get_metadata(&packet, Builder::MESSAGE_TYPE)
            .context("Missing handshake message type")?
            .parse::<u8>()?;

        let mut payload_frames = get_all_metadata(&packet, Self::FRAGMENT);
        if payload_frames.is_empty() {
            payload_frames.push(&frame_num);
        }
        let payload_frames: HashSet<&str> = HashSet::from_iter(payload_frames);

        let mut payloads = Vec::new();
        for packet in tcp_payloads {
            if let Some(frame) = get_metadata(packet, Builder::FRAME_NUM) {
                if payload_frames.contains(frame) {
                    let payload = get_metadata(packet, Builder::TCP_PAYLOAD)
                        .context("Missing tcp payload")?;
                    payloads.push(payload.replace(':', ""));
                }
            }
        }

        let count = get_metadata(&packet, Self::FRAGMENTS_COUNT).unwrap_or("1");
        if count != payloads.len().to_string() {
            bail!("Unable to find all tcp payloads for tls message")
        }

        Ok(Self {
            message_type,
            packet,
            payloads,
            frame_num,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Builder {
    message_type: Option<u8>,
    capture_file: Option<String>,
}

impl Builder {
    const TCP_PAYLOAD: &'static str = "tcp.payload";
    const FRAME_NUM: &'static str = "frame.number";
    const MESSAGE_TYPE: &'static str = "tls.handshake.type";

    pub(crate) fn set_type(&mut self, message_type: u8) -> &mut Self {
        self.message_type = Some(message_type);
        self
    }

    pub fn set_capture_file(&mut self, file: &str) -> &mut Self {
        self.capture_file = Some(file.to_string());
        self
    }

    fn build_from_capture(self, capture: rtshark::RTSharkBuilderReady) -> Result<Vec<Message>> {
        let tcp_capture = capture
            .display_filter(Self::TCP_PAYLOAD)
            .metadata_whitelist(Self::TCP_PAYLOAD)
            .metadata_whitelist(Self::FRAME_NUM)
            .spawn()?;
        let payloads = read_all(tcp_capture);

        let filter = if let Some(message_type) = self.message_type {
            format!("{} == {}", Self::MESSAGE_TYPE, message_type)
        } else {
            Self::MESSAGE_TYPE.to_string()
        };
        let message_capture = capture.display_filter(&filter).spawn()?;

        let mut messages = Vec::new();
        for packet in read_all(message_capture) {
            let frame_num = get_metadata(&packet, Builder::FRAME_NUM)
                .context("Missing frame number")?
                .to_string();

            let context_msg = format!("Failed to parse frame {}", &frame_num);
            let message =
                Message::from_packet(packet, frame_num, &payloads).context(context_msg)?;

            messages.push(message);
        }
        Ok(messages)
    }

    pub(crate) fn build(mut self) -> Result<Vec<Message>> {
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
        assert_eq!(first.payloads.len(), 3);
        let bytes = first.to_bytes()?;
        // Correct length read from wireshark
        assert_eq!(bytes.len(), 16262);

        Ok(())
    }

    #[test]
    fn multiple_handshakes() -> Result<()> {
        let mut builder = Builder::default();
        builder.set_capture_file("data/multiple_hellos.pcap");
        let messages = builder.build()?;
        let count = messages.iter().filter(|m| m.message_type == 1).count();
        assert_eq!(count, 5);
        Ok(())
    }

    #[test]
    fn from_pcaps() -> Result<()> {
        let pcaps = all_pcaps();

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
