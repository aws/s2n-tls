use s2n_codec::{
    DecoderBuffer, DecoderValue,
    decoder::{PrefixedBlob, PrefixedList},
};

use crate::static_lists::{Cipher, Group, Signature, Version};

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
#[allow(dead_code)]
pub(crate) struct ClientHello<'a> {
    pub protocol_version: Version,
    pub random: [u8; 32],
    pub legacy_session_id: PrefixedBlob<'a, u8>,
    pub cipher_suites: PrefixedList<'a, u16, Cipher>,
    pub compression_methods: PrefixedBlob<'a, u8>,
    pub extensions: Option<PrefixedBlob<'a, u16>>,
}

impl<'a> DecoderValue<'a> for ClientHello<'a> {
    fn decode(bytes: s2n_codec::DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (protocol_version, bytes) = bytes.decode()?;
        let (random, bytes) = bytes.decode()?;
        let (legacy_session_id, bytes) = bytes.decode()?;
        let (cipher_suites, bytes) = bytes.decode()?;
        let (compression_methods, bytes) = bytes.decode()?;
        let (extensions, bytes) = bytes.decode()?;

        let value = Self {
            protocol_version,
            random,
            legacy_session_id,
            cipher_suites,
            compression_methods,
            extensions,
        };

        Ok((value, bytes))
    }
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.2.7
pub(crate) struct SupportedGroups<'a> {
    pub named_group_list: PrefixedList<'a, u16, Group>,
}

impl<'a> DecoderValue<'a> for SupportedGroups<'a> {
    fn decode(bytes: DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (named_group_list, bytes) = bytes.decode()?;
        let value = Self { named_group_list };
        Ok((value, bytes))
    }
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.2.1
pub(crate) struct SupportedVersionsClientHello<'a> {
    pub versions: PrefixedList<'a, u8, Version>,
}

impl<'a> DecoderValue<'a> for SupportedVersionsClientHello<'a> {
    fn decode(bytes: DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (versions, bytes) = bytes.decode()?;
        let value = Self { versions };
        Ok((value, bytes))
    }
}

/// Defined in https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
pub(crate) struct SignatureSchemeList<'a> {
    pub supported_signature_algorithms: PrefixedList<'a, u16, Signature>,
}

impl<'a> DecoderValue<'a> for SignatureSchemeList<'a> {
    fn decode(bytes: DecoderBuffer<'a>) -> s2n_codec::DecoderBufferResult<'a, Self> {
        let (supported_signature_algorithms, bytes) = bytes.decode()?;
        let value = Self {
            supported_signature_algorithms,
        };
        Ok((value, bytes))
    }
}
