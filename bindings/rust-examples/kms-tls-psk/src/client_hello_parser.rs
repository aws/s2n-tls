// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::ErrorKind;

use crate::{
    codec::{DecodeByteSource, DecodeValue},
    prefixed_list::{PrefixedBlob, PrefixedList},
};

/// retrieve the PskIdentity items from the Psk extension in the ClientHello.
pub fn retrieve_identities(
    client_hello: &s2n_tls::client_hello::ClientHello,
) -> std::io::Result<PrefixedList<PskIdentity, u16>> {
    let bytes = client_hello.raw_message()?;
    let buffer = bytes.as_slice();
    let client_hello = ClientHello::decode_from_exact(buffer)?;

    let maybe_psks = client_hello
        .extensions
        .list()
        .iter()
        .find(|e| e.extension_type == ExtensionType::PreSharedKey);

    match maybe_psks {
        Some(extension) => {
            let identities =
                PresharedKeyClientHello::decode_from_exact(extension.extension_data.blob())?;
            Ok(identities.identities)
        }
        None => Err(std::io::Error::new(
            ErrorKind::Unsupported,
            "client hello did not contain PSKs".to_owned(),
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HandshakeType {
    ClientHello,
    Unknown(u8),
}

impl DecodeValue for HandshakeType {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (value, remaining) = u8::decode_from(buffer)?;
        let protocol = match value {
            1 => Self::ClientHello,
            x => Self::Unknown(x),
        };
        Ok((protocol, remaining))
    }
}

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u16)]
enum ExtensionType {
    PreSharedKey = 41,
    Unknown(u16),
}

impl DecodeValue for ExtensionType {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (value, remaining) = u16::decode_from(buffer)?;
        let protocol = match value {
            41 => Self::PreSharedKey,
            x => Self::Unknown(x),
        };
        Ok((protocol, remaining))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Protocol {
    SSLv3,
    TLSv1_0,
    TLSv1_1,
    TLSv1_2,
    TLSv1_3,
    Unknown(u16),
}

impl DecodeValue for Protocol {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (value, remaining) = u16::decode_from(buffer)?;
        let protocol = match value {
            0x0300 => Self::SSLv3,
            0x0301 => Self::TLSv1_0,
            0x0302 => Self::TLSv1_1,
            0x0303 => Self::TLSv1_2,
            0x0304 => Self::TLSv1_3,
            x => Self::Unknown(x),
        };
        Ok((protocol, remaining))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskIdentity {
    pub identity: PrefixedBlob<u16>,
    pub obfuscated_ticket_age: u32,
}

impl DecodeValue for PskIdentity {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (identity, buffer) = buffer.decode_value()?;
        let (obfuscated_ticket_age, buffer) = buffer.decode_value()?;

        let value = Self {
            identity,
            obfuscated_ticket_age,
        };

        Ok((value, buffer))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PskBinderEntry {
    entry: PrefixedBlob<u8>,
}

impl DecodeValue for PskBinderEntry {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (entry, buffer) = buffer.decode_value()?;

        let value = Self { entry };

        Ok((value, buffer))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresharedKeyClientHello {
    identities: PrefixedList<PskIdentity, u16>,
    binders: PrefixedList<PskBinderEntry, u16>,
}

impl DecodeValue for PresharedKeyClientHello {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (identities, buffer) = buffer.decode_value()?;
        let (binders, buffer) = buffer.decode_value()?;

        let value = Self {
            identities,
            binders,
        };

        Ok((value, buffer))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    protocol_version: Protocol,
    random: [u8; 32],
    session_id: PrefixedBlob<u8>,
    offered_ciphers: PrefixedBlob<u16>,
    compression_methods: PrefixedBlob<u8>,
    extensions: PrefixedList<Extension, u16>,
}

impl DecodeValue for ClientHello {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (protocol_version, buffer) = buffer.decode_value()?;
        let (random, buffer) = buffer.decode_value()?;
        let (session_id, buffer) = buffer.decode_value()?;
        let (offered_ciphers, buffer) = buffer.decode_value()?;
        let (compression_methods, buffer) = buffer.decode_value()?;
        let (extensions, buffer) = buffer.decode_value()?;

        let value = Self {
            protocol_version,
            random,
            session_id,
            offered_ciphers,
            compression_methods,
            extensions,
        };

        Ok((value, buffer))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Extension {
    extension_type: ExtensionType,
    extension_data: PrefixedBlob<u16>,
}

impl DecodeValue for Extension {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (extension_type, buffer) = buffer.decode_value()?;
        let (extension_data, buffer) = buffer.decode_value()?;

        let value = Self {
            extension_type,
            extension_data,
        };

        Ok((value, buffer))
    }
}
