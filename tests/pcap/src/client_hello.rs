// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::handshake_message::Builder as MessageBuilder;
use crate::handshake_message::Message;
use anyhow::*;
use std::option::Option;

use crate::capture::*;

#[derive(Debug, Clone, Default)]
pub struct ClientHello {
    pub message: Message,
    pub ja3_hash: Option<String>,
    pub ja3_str: Option<String>,
}

impl ClientHello {
    const JA3_HASH: &'static str = "tls.handshake.ja3";
    const JA3_STR: &'static str = "tls.handshake.ja3_full";

    fn from_message(message: Message) -> Self {
        let packet = &message.packet;
        let ja3_hash = get_metadata(packet, Self::JA3_HASH).map(str::to_string);
        let ja3_str = get_metadata(packet, Self::JA3_STR).map(str::to_string);
        Self {
            message,
            ja3_hash,
            ja3_str,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Builder(MessageBuilder);

impl Builder {
    pub fn inner(&mut self) -> &mut MessageBuilder {
        &mut self.0
    }

    pub fn build(mut self) -> Result<Vec<ClientHello>> {
        self.0.set_type(1);

        let mut client_hellos = Vec::new();
        for message in self.0.build()? {
            client_hellos.push(ClientHello::from_message(message));
        }
        Ok(client_hellos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiple_hellos() -> Result<()> {
        let mut builder = Builder::default();
        builder
            .inner()
            .set_capture_file("data/multiple_hellos.pcap");
        let hellos = builder.build()?;
        assert_eq!(hellos.len(), 5);
        Ok(())
    }

    #[test]
    fn from_pcaps() -> Result<()> {
        let pcaps = all_pcaps();

        for pcap in pcaps {
            let mut builder = Builder::default();
            builder.inner().set_capture_file(&pcap);
            let hellos = builder.build().unwrap();

            assert!(!hellos.is_empty());
            for hello in hellos {
                assert!(hello.ja3_hash.is_some());
                assert!(hello.ja3_str.is_some());
            }
        }

        Ok(())
    }
}
