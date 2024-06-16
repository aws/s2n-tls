// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::handshake_message::HandshakeMessage;
use anyhow::*;
use std::option::Option;

#[derive(Debug, Clone, Default)]
pub struct ClientHello(HandshakeMessage);

impl ClientHello {
    /// ClientHello message type, as defined in the TLS RFC.
    /// See https://datatracker.ietf.org/doc/html/rfc8446#section-4
    const MESSAGE_TYPE: u8 = 1;

    const JA3_HASH: &'static str = "tls.handshake.ja3";
    pub fn ja3_hash(&self) -> Option<String> {
        self.0.packet.metadata(Self::JA3_HASH).map(str::to_owned)
    }

    const JA3_STR: &'static str = "tls.handshake.ja3_full";
    pub fn ja3_string(&self) -> Option<String> {
        self.0.packet.metadata(Self::JA3_STR).map(str::to_owned)
    }

    pub fn message(&self) -> &HandshakeMessage {
        &self.0
    }
}

impl crate::handshake_message::Builder {
    pub fn build_client_hellos(mut self) -> Result<Vec<ClientHello>> {
        self.set_type(ClientHello::MESSAGE_TYPE);
        let client_hellos = self.build()?.into_iter().map(ClientHello).collect();
        Ok(client_hellos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake_message::Builder;

    #[test]
    fn multiple_hellos() -> Result<()> {
        let mut builder = Builder::default();
        builder.set_capture_file("data/multiple_hellos.pcap");
        let hellos = builder.build_client_hellos().unwrap();
        assert_eq!(hellos.len(), 5);
        Ok(())
    }

    #[test]
    fn from_pcaps() -> Result<()> {
        let pcaps = crate::all_pcaps();
        for pcap in pcaps {
            let mut builder = Builder::default();
            builder.set_capture_file(&pcap);
            let hellos = builder.build_client_hellos().unwrap();
            assert!(!hellos.is_empty());
        }
        Ok(())
    }
}
