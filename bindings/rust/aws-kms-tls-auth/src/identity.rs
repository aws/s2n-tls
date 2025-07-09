// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::{DecodeByteSource, DecodeValue, EncodeBytesSink, EncodeValue},
    prefixed_list::PrefixedBlob,
    AES_256_GCM_KEY_LEN, AES_256_GCM_NONCE_LEN,
};
use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM};
use std::{hash::Hash, io::ErrorKind};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
enum KmsPskFormat {
    V1 = 1,
}

impl EncodeValue for KmsPskFormat {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        let byte = *self as u8;
        buffer.encode_value(&byte)?;
        Ok(())
    }
}

impl DecodeValue for KmsPskFormat {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (value, buffer) = u8::decode_from(buffer)?;
        match value {
            1 => Ok((Self::V1, buffer)),
            _ => Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("{value} is not a valid KmsPskFormat"),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObfuscationKey {
    name: Vec<u8>,
    material: [u8; AES_256_GCM_KEY_LEN],
}

impl ObfuscationKey {
    pub fn new(name: Vec<u8>, material: [u8; AES_256_GCM_KEY_LEN]) -> anyhow::Result<Self> {
        if material.iter().all(|b| *b == 0) {
            anyhow::bail!("material can not be all zeros");
        }
        Ok(ObfuscationKey { name, material })
    }
    #[cfg(test)]
    pub(crate) fn random_test_key() -> Self {
        use aws_lc_rs::rand::SecureRandom;

        let rng = aws_lc_rs::rand::SystemRandom::new();
        debug_assert_eq!(AES_256_GCM.key_len(), AES_256_GCM_KEY_LEN);
        let mut key = [0; AES_256_GCM_KEY_LEN];
        let mut name = [0; 16];

        rng.fill(&mut key).unwrap();
        rng.fill(&mut name).unwrap();

        Self {
            name: name.into(),
            material: key,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct KmsTlsPskIdentity {
    version: KmsPskFormat,
    obfuscation_key_name: PrefixedBlob<u16>,
    nonce: [u8; AES_256_GCM_NONCE_LEN],
    // the KMS datakey ciphertext, encrypted under the obfuscation key
    obfuscated_identity: PrefixedBlob<u16>,
}

impl EncodeValue for KmsTlsPskIdentity {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.encode_value(&self.version)?;
        buffer.encode_value(&self.obfuscation_key_name)?;
        buffer.encode_value(&self.nonce)?;
        buffer.encode_value(&self.obfuscated_identity)?;
        Ok(())
    }
}

impl DecodeValue for KmsTlsPskIdentity {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (version, buffer) = buffer.decode_value()?;
        let (obfuscation_key_name, buffer) = buffer.decode_value()?;
        let (nonce, buffer) = buffer.decode_value()?;
        let (obfuscated_identity, buffer) = buffer.decode_value()?;

        let value = Self {
            version,
            obfuscation_key_name,
            nonce,
            obfuscated_identity,
        };

        Ok((value, buffer))
    }
}

impl KmsTlsPskIdentity {
    /// Create a KmsTlsPskIdentity
    ///
    /// * `ciphertext_data_key`: The ciphertext returned from the KMS generateDataKey
    ///                          API.
    /// * `obfuscation_key`: The key that will be used to obfuscate the ciphertext,
    ///                      preventing any details about the ciphertext from being
    ///                      read on the wire.
    pub fn new(ciphertext_datakey: &[u8], obfuscation_key: &ObfuscationKey) -> Self {
        let mut in_out = ciphertext_datakey.to_vec();
        let key = RandomizedNonceKey::new(&AES_256_GCM, &obfuscation_key.material).unwrap();
        let nonce = key
            .seal_in_place_append_tag(Aad::empty(), &mut in_out)
            .unwrap();
        let nonce_bytes = nonce.as_ref();

        Self {
            version: KmsPskFormat::V1,
            obfuscation_key_name: PrefixedBlob::new(obfuscation_key.name.clone()),
            nonce: *nonce_bytes,
            obfuscated_identity: PrefixedBlob::new(in_out),
        }
    }

    /// de-obfuscate the Psk Identity, returning the ciphertext datakey to be decrypted
    /// with KMS.
    pub fn deobfuscate_datakey(
        &self,
        available_obfuscation_keys: &[ObfuscationKey],
    ) -> anyhow::Result<Vec<u8>> {
        let maybe_key = available_obfuscation_keys
            .iter()
            .find(|key| key.name == self.obfuscation_key_name.blob());
        let obfuscation_key = match maybe_key {
            Some(key) => key,
            None => {
                anyhow::bail!(
                    "unable to deobfuscate: {} not available",
                    hex::encode(self.obfuscation_key_name.blob()),
                )
            }
        };

        let key = RandomizedNonceKey::new(&AES_256_GCM, &obfuscation_key.material)?;

        let mut in_out = Vec::from(self.obfuscated_identity.blob());
        let decrypted_length = key
            .open_in_place(Nonce::from(&self.nonce), Aad::empty(), &mut in_out)?
            .len();
        in_out.truncate(decrypted_length);
        Ok(in_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// serializing and deserializing a PSK Identity should result in the same struct
    #[test]
    fn round_trip() {
        let ciphertext_datakey = b"i am totally a KMS ciphertext";
        let obfuscation_key = ObfuscationKey::random_test_key();

        let identity = KmsTlsPskIdentity::new(ciphertext_datakey.as_slice(), &obfuscation_key);

        let serialized_identity = identity.encode_to_vec().unwrap();

        let (deserialized_identity, remaining) =
            KmsTlsPskIdentity::decode_from(&serialized_identity).unwrap();
        assert!(remaining.is_empty());

        assert_eq!(deserialized_identity, identity);
    }

    /// after obfuscation, the ciphertext is not visible on the wire
    #[test]
    fn obfuscation() {
        let ciphertext_datakey = b"i am totally a KMS ciphertext";
        let obfuscation_key = ObfuscationKey::random_test_key();

        let identity = KmsTlsPskIdentity::new(ciphertext_datakey.as_slice(), &obfuscation_key);
        let wire_bytes = identity.encode_to_vec().unwrap();

        let ciphertext_in_wire = wire_bytes
            .windows(ciphertext_datakey.len())
            .any(|chunk| chunk == ciphertext_datakey.as_slice());
        assert!(!ciphertext_in_wire);
    }

    #[test]
    fn deobfuscation() {
        let ciphertext_datakey = b"i am totally a KMS ciphertext";
        let obfuscation_key = ObfuscationKey::random_test_key();

        let identity = KmsTlsPskIdentity::new(ciphertext_datakey.as_slice(), &obfuscation_key);

        // success with correct key
        {
            let only_correct_key = vec![obfuscation_key.clone()];
            let deobfuscated = identity.deobfuscate_datakey(&only_correct_key).unwrap();
            assert_eq!(deobfuscated.as_slice(), ciphertext_datakey.as_slice());
        }

        // success with correct key and others
        {
            let one_correct_key = vec![
                ObfuscationKey::random_test_key(),
                obfuscation_key.clone(),
                ObfuscationKey::random_test_key(),
            ];
            let deobfuscated = identity.deobfuscate_datakey(&one_correct_key).unwrap();
            assert_eq!(deobfuscated.as_slice(), ciphertext_datakey.as_slice());
        }

        // failure with wrong name
        {
            let incorrect_key = vec![ObfuscationKey::random_test_key()];
            let failed_deobfuscate = identity.deobfuscate_datakey(&incorrect_key).unwrap_err();
            let explanation = format!("{failed_deobfuscate:?}");
            assert!(explanation.contains("unable to deobfuscate"));
        }

        // failure with right name but wrong material
        {
            let mut modified_key = obfuscation_key.clone();
            // modify random piece of key
            modified_key.material[2] = modified_key.material[2].wrapping_add(1);
            let failed_deobfuscate = identity.deobfuscate_datakey(&[modified_key]).unwrap_err();
            // this is the direct error message that aws-lc returns
            assert!(failed_deobfuscate.to_string().contains("Unspecified"));
        }
    }

    /// The encoded PSK Identity from the 0.0.1 version of the library was checked
    /// in. If we ever fail to deserialize this STOP! You are about to make a
    /// breaking change. You must find a way to make your change backwards
    /// compatible.
    #[test]
    fn backwards_compatibility() {
        const ENCODED_IDENTITY: &[u8] = include_bytes!("../resources/psk_identity.bin");
        const CIPHERTEXT: &[u8] = b"this is a test KMS ciphertext";

        const OBFUSCATION_KEY_NAME: &[u8] = b"obfuscation key prime";
        const OBFUSCATION_KEY_MATERIAL: [u8; AES_256_GCM_KEY_LEN] = [
            91, 109, 160, 46, 132, 41, 29, 134, 11, 41, 208, 78, 101, 132, 138, 80, 88, 32, 182,
            207, 80, 45, 37, 93, 83, 11, 69, 218, 200, 203, 55, 66,
        ];

        let obfuscation_key = ObfuscationKey {
            name: OBFUSCATION_KEY_NAME.to_vec(),
            material: OBFUSCATION_KEY_MATERIAL,
        };

        let (deserialized_identity, remaining) =
            KmsTlsPskIdentity::decode_from(ENCODED_IDENTITY).unwrap();
        assert!(remaining.is_empty());

        let datakey_ciphertext = deserialized_identity
            .deobfuscate_datakey(&[obfuscation_key])
            .unwrap();
        assert_eq!(datakey_ciphertext, CIPHERTEXT);
    }
}
