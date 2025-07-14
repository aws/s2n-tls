// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::{DecodeByteSource, DecodeValue, EncodeBytesSink, EncodeValue},
    prefixed_list::PrefixedBlob,
    AES_256_GCM_SIV_KEY_LEN, AES_256_GCM_SIV_NONCE_LEN, PSK_IDENTITY_VALIDITY,
};
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM_SIV};
use std::{
    hash::Hash,
    io::ErrorKind,
    time::{Duration, SystemTime},
};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
enum PskVersion {
    V1 = 1,
}

impl EncodeValue for PskVersion {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        let byte = *self as u8;
        buffer.encode_value(&byte)?;
        Ok(())
    }
}

impl DecodeValue for PskVersion {
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
    material: Vec<u8>,
}

impl ObfuscationKey {
    /// Create an obfuscation key.
    ///
    /// Currently, the `material` field must be 32 bytes.
    pub fn new(name: Vec<u8>, material: Vec<u8>) -> anyhow::Result<Self> {
        if name.is_empty() {
            // While we could support this, it is easier to constrain inputs to
            // "normal" values.
            anyhow::bail!("name must not be empty");
        }
        if material.len() != AES_256_GCM_SIV_KEY_LEN {
            anyhow::bail!("material must be 32 bytes, but was {}", material.len())
        }
        if material.iter().all(|b| *b == 0) {
            anyhow::bail!("material can not be all zeros");
        }
        Ok(ObfuscationKey { name, material })
    }

    #[cfg(test)]
    pub(crate) fn random_test_key() -> Self {
        use aws_lc_rs::rand::SecureRandom;

        let rng = aws_lc_rs::rand::SystemRandom::new();
        debug_assert_eq!(AES_256_GCM_SIV.key_len(), AES_256_GCM_SIV_KEY_LEN);
        let mut key = vec![0; AES_256_GCM_SIV_KEY_LEN];
        let mut name = [0; 16];

        rng.fill(&mut key).unwrap();
        rng.fill(&mut name).unwrap();

        Self {
            name: name.into(),
            material: key,
        }
    }

    fn aes_256_key(&self) -> anyhow::Result<LessSafeKey> {
        Ok(LessSafeKey::new(UnboundKey::new(
            &AES_256_GCM_SIV,
            &self.material,
        )?))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct KmsDataKey {
    pub ciphertext: Vec<u8>,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct PskIdentity {
    version: PskVersion,
    obfuscation_key_name: PrefixedBlob<u16>,
    nonce: [u8; AES_256_GCM_SIV_NONCE_LEN],
    obfuscated_fields: PrefixedBlob<u32>,
}

pub(crate) struct ObfuscatedIdentityFields {
    seconds_since_epoch: u64,
    ciphertext_datakey: PrefixedBlob<u32>,
}

impl EncodeValue for PskIdentity {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.encode_value(&self.version)?;
        buffer.encode_value(&self.obfuscation_key_name)?;
        buffer.encode_value(&self.nonce)?;
        buffer.encode_value(&self.obfuscated_fields)?;
        Ok(())
    }
}

impl DecodeValue for PskIdentity {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (version, buffer) = buffer.decode_value()?;
        let (obfuscation_key_name, buffer) = buffer.decode_value()?;
        let (nonce, buffer) = buffer.decode_value()?;
        let (obfuscated_identity, buffer) = buffer.decode_value()?;

        let value = Self {
            version,
            obfuscation_key_name,
            nonce,
            obfuscated_fields: obfuscated_identity,
        };

        Ok((value, buffer))
    }
}

impl EncodeValue for ObfuscatedIdentityFields {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.encode_value(&self.seconds_since_epoch)?;
        buffer.encode_value(&self.ciphertext_datakey)?;
        Ok(())
    }
}

impl DecodeValue for ObfuscatedIdentityFields {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (seconds_since_epoch, buffer) = buffer.decode_value()?;
        let (ciphertext_datakey, buffer) = buffer.decode_value()?;

        let value = Self {
            seconds_since_epoch,
            ciphertext_datakey,
        };

        Ok((value, buffer))
    }
}

impl PskIdentity {
    /// Create a PskIdentity
    ///
    /// * `ciphertext_data_key`: The ciphertext returned from the KMS generateDataKey
    ///   API.
    /// * `obfuscation_key`: The key that will be used to obfuscate the ciphertext,
    ///   preventing any details about the ciphertext from being on the wire.
    pub fn new(
        ciphertext_datakey: &[u8],
        obfuscation_key: &ObfuscationKey,
    ) -> anyhow::Result<Self> {
        let inner_fields = ObfuscatedIdentityFields {
            seconds_since_epoch: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            ciphertext_datakey: PrefixedBlob::new(ciphertext_datakey.to_vec())?,
        };

        let (inner_fields, nonce_bytes) = inner_fields.obfuscate(obfuscation_key)?;

        let identity = Self {
            version: PskVersion::V1,
            obfuscation_key_name: PrefixedBlob::new(obfuscation_key.name.clone())?,
            nonce: nonce_bytes,
            obfuscated_fields: PrefixedBlob::new(inner_fields)?,
        };
        Ok(identity)
    }

    /// de-obfuscate the Psk Identity, returning the ciphertext datakey to be decrypted
    /// with KMS.
    ///
    /// This method is time aware, and will fail if the age is greater than
    /// [`PSK_IDENTITY_VALIDITY`].
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

        let obfuscated_fields = ObfuscatedIdentityFields::deobfuscate(
            obfuscation_key,
            self.obfuscated_fields.blob(),
            &self.nonce,
        )?;

        Ok(obfuscated_fields.ciphertext_datakey.take_blob())
    }
}

impl ObfuscatedIdentityFields {
    fn obfuscate(
        &self,
        obfuscation_key: &ObfuscationKey,
    ) -> anyhow::Result<(Vec<u8>, [u8; AES_256_GCM_SIV_NONCE_LEN])> {
        let mut in_out = self.encode_to_vec()?;

        let key = obfuscation_key.aes_256_key()?;
        let nonce_bytes = Self::random_nonce()?;
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::empty(),
            &mut in_out,
        )?;

        Ok((in_out, nonce_bytes))
    }

    fn deobfuscate(
        obfuscation_key: &ObfuscationKey,
        obfuscated_blob: &[u8],
        nonce: &[u8; AES_256_GCM_SIV_NONCE_LEN],
    ) -> anyhow::Result<Self> {
        let mut in_out = obfuscated_blob.to_vec();

        let key = obfuscation_key.aes_256_key()?;
        let decrypted_length = key
            .open_in_place(Nonce::from(nonce), Aad::empty(), &mut in_out)?
            .len();
        in_out.truncate(decrypted_length);

        let obfuscated_fields = ObfuscatedIdentityFields::decode_from_exact(&in_out)?;
        obfuscated_fields.check_age()?;
        Ok(obfuscated_fields)
    }

    fn random_nonce() -> anyhow::Result<[u8; AES_256_GCM_SIV_NONCE_LEN]> {
        let mut nonce = [0; AES_256_GCM_SIV_NONCE_LEN];
        aws_lc_rs::rand::fill(&mut nonce)?;
        Ok(nonce)
    }

    fn check_age(&self) -> anyhow::Result<()> {
        let creation_time = {
            let since_epoch = Duration::from_secs(self.seconds_since_epoch);
            let maybe_creation_time = SystemTime::UNIX_EPOCH.checked_add(since_epoch);
            if let Some(creation_time) = maybe_creation_time {
                creation_time
            } else {
                anyhow::bail!("identity creation time could not be represented");
            }
        };

        let identity_age = creation_time.elapsed()?;
        if identity_age > PSK_IDENTITY_VALIDITY {
            anyhow::bail!(
                "Too Old: PSK age was {:?}, but must be less than {:?}",
                identity_age,
                PSK_IDENTITY_VALIDITY
            );
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{CIPHERTEXT_DATAKEY_A, CONSTANT_OBFUSCATION_KEY};

    use super::*;

    #[test]
    fn invalid_keys() {
        let test_name = b"obfuscation key name".to_vec();

        let all_zero_err = ObfuscationKey::new(test_name.clone(), vec![0; 32]).unwrap_err();
        assert_eq!(all_zero_err.to_string(), "material can not be all zeros");

        let mut invalid_length = vec![0; 53];
        invalid_length[3] = 1;
        let invalid_length_err = ObfuscationKey::new(test_name, invalid_length).unwrap_err();
        assert_eq!(
            invalid_length_err.to_string(),
            "material must be 32 bytes, but was 53"
        );

        let valid_material = {
            let mut material = vec![0; 32];
            material[3] = 1;
            material
        };
        let invalid_name_err = ObfuscationKey::new(Vec::new(), valid_material).unwrap_err();
        assert_eq!(invalid_name_err.to_string(), "name must not be empty");
    }

    /// serializing and deserializing a PSK Identity should result in the same struct
    #[test]
    fn round_trip() {
        let ciphertext_datakey = b"i am totally a KMS ciphertext";
        let obfuscation_key = ObfuscationKey::random_test_key();

        let identity = PskIdentity::new(ciphertext_datakey.as_slice(), &obfuscation_key).unwrap();

        let serialized_identity = identity.encode_to_vec().unwrap();

        let (deserialized_identity, remaining) =
            PskIdentity::decode_from(&serialized_identity).unwrap();
        assert!(remaining.is_empty());

        assert_eq!(deserialized_identity, identity);
    }

    /// after obfuscation, the ciphertext is not visible on the wire
    #[test]
    fn obfuscation() {
        let ciphertext_datakey = b"i am totally a KMS ciphertext";
        let obfuscation_key = ObfuscationKey::random_test_key();

        let identity = PskIdentity::new(ciphertext_datakey.as_slice(), &obfuscation_key).unwrap();
        let wire_bytes = identity.encode_to_vec().unwrap();

        let ciphertext_in_wire = wire_bytes
            .windows(ciphertext_datakey.len())
            .any(|chunk| chunk == ciphertext_datakey.as_slice());
        assert!(!ciphertext_in_wire);
    }

    #[test]
    fn deobfuscation() -> anyhow::Result<()> {
        let ciphertext_datakey = b"i am totally a KMS ciphertext";
        let obfuscation_key = ObfuscationKey::random_test_key();

        let identity = PskIdentity::new(ciphertext_datakey.as_slice(), &obfuscation_key)?;

        // success with correct key
        {
            let only_correct_key = vec![obfuscation_key.clone()];
            let deobfuscated = identity.deobfuscate_datakey(&only_correct_key)?;
            assert_eq!(deobfuscated.as_slice(), ciphertext_datakey.as_slice());
        }

        // success with correct key and others
        {
            let one_correct_key = vec![
                ObfuscationKey::random_test_key(),
                obfuscation_key.clone(),
                ObfuscationKey::random_test_key(),
            ];
            let deobfuscated = identity.deobfuscate_datakey(&one_correct_key)?;
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
        Ok(())
    }

    #[test]
    fn deobfuscation_with_old_identity() {
        let obfuscation_key = ObfuscationKey::random_test_key();
        let one_minute_old_identity = {
            let one_minute_ago = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .saturating_sub(PSK_IDENTITY_VALIDITY + Duration::from_secs(10))
                .as_secs();

            let inner_fields = ObfuscatedIdentityFields {
                seconds_since_epoch: one_minute_ago,
                ciphertext_datakey: PrefixedBlob::new(CIPHERTEXT_DATAKEY_A.to_vec()).unwrap(),
            };

            let (inner_fields, nonce_bytes) = inner_fields.obfuscate(&obfuscation_key).unwrap();

            PskIdentity {
                version: PskVersion::V1,
                obfuscation_key_name: PrefixedBlob::new(obfuscation_key.name.clone()).unwrap(),
                nonce: nonce_bytes,
                obfuscated_fields: PrefixedBlob::new(inner_fields).unwrap(),
            }
        };

        let too_old_err = one_minute_old_identity
            .deobfuscate_datakey(&[obfuscation_key])
            .unwrap_err();
        // e.g. "Too Old: PSK age was 1762.201972884s, but must be less than 60s"
        assert!(too_old_err.to_string().contains("Too Old: PSK age was"));
    }

    /// The encoded PSK Identity from the 0.0.1 version of the library was checked
    /// in. If we ever fail to deserialize this STOP! You are about to make a
    /// breaking change. You must find a way to make your change backwards
    /// compatible.
    #[test]
    fn backwards_compatibility() {
        const ENCODED_IDENTITY: &[u8] = include_bytes!("../resources/psk_identity.bin");
        const CIPHERTEXT: &[u8] = b"this is a test KMS ciphertext";

        let (deserialized_identity, remaining) =
            PskIdentity::decode_from(ENCODED_IDENTITY).unwrap();
        assert!(remaining.is_empty());

        // The API is deliberately designed to make it difficult to avoid checking
        // the age of the PSK. This is still a useful test because age validation
        // happens after parsing everything. As long as we are seeing the age
        // error, then there is a high degree of confidence that there are no
        // backwards incompatible changes.
        let too_old_err = deserialized_identity
            .deobfuscate_datakey(&[CONSTANT_OBFUSCATION_KEY.clone()])
            .unwrap_err();

        // e.g. "Too Old: PSK age was 1762.201972884s, but must be less than 60s"
        assert!(too_old_err.to_string().contains("Too Old: PSK age was"));
    }
}
