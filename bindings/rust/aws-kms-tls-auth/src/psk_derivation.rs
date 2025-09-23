// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! There are three components to the HMAC PSK Design
//!
//! ## Epoch Secret
//!
//! The epoch secret is generated using the KMS GenerateMac API. The "message"
//! being signed is the number of days elapsed since the unix epoch, represented
//! as a `u64` in big-endian format.
//!
//! The KMS key must use an HMAC-SHA384 keyspec. This is not currently library
//! configurable.
//!
//! ## PSK Secret
//!
//! First the client generates a random `session_name` to be used as a nonce. This
//! is then used with the epoch_secret in an HKDF to derive a connection-specific
//! secret.
//!
//! ```text
//! connection_secret = HKDF(
//!     secret: epoch_secret
//!     info: session_name
//!     salt: null
//! )
//! ```
//!
//! ## PSK Identity
//!
//! The PSK identity is sent in plaintext in the client hello. Note that a server
//! ([`crate::PskReceiver`]) supports trusting multiple KMS keys, which allows for
//! rotation/transitioning the underlying KMS key.
//!
//! If a server trusts both keyA and keyB, then the client will need to
//! communicate which key it used to derive its PSK. The naive solution would be
//! to just include keyA or keyB in plaintext in the PSK Identity. However, this
//! would leak information about “fleet membership”, because it is sent in the
//! clear. Ideally, the PSK identity would not leak this information.
//!
//! To do this we calculate a `kms_key_binder` to include in the PSK Identity. This
//! incorporates
//! - kms key arn: the key that was used to generate the daily secret
//! - session name: this makes the kms key binder unique per connection, preventing
//!   information from being correlated across multiple connections from a single
//!   client.
//! - epoch_secret: without incorporating this secret, an attacker would be able
//!   check if the kms_key_binder was valid for some specific KMS key.

use crate::{
    codec::{DecodeByteSource, DecodeValue, EncodeBytesSink, EncodeValue},
    prefixed_list::PrefixedBlob,
    KeyArn,
};
use aws_lc_rs::{
    digest::{self},
    hkdf,
    rand::SecureRandom,
};
use aws_sdk_kms::{primitives::Blob, types::MacAlgorithmSpec, Client};
use s2n_tls::error::Error as S2NError;
use std::{fmt::Debug, hash::Hash, io::ErrorKind};

const SHA384_DIGEST_SIZE: usize = 48;
const SESSION_NAME_LENGTH: usize = 16;

// V1 was used for an earlier KMS data-key based solution and is no longer supported
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(u8)]
pub enum PskVersion {
    V2 = 2,
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
            2 => Ok((Self::V2, buffer)),
            _ => Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("{value} is not a valid KmsPskFormat"),
            )),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EpochSecret {
    /// the ARN of the KMS HMAC key
    pub key_arn: KeyArn,
    /// the key epoch, which is the number of days elapsed since the unix epoch
    pub key_epoch: u64,
    /// the secret material from the generateMAC API
    pub secret: Vec<u8>,
}

impl Debug for EpochSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochSecret")
            .field("key_arn", &self.key_arn)
            .field("key_epoch", &self.key_epoch)
            .field("secret", &"<REDACTED>")
            .finish()
    }
}

impl EpochSecret {
    /// Fetch the secret for `epoch` from KMS.
    pub async fn fetch_epoch_secret(
        kms_client: &Client,
        key_arn: &KeyArn,
        epoch: u64,
    ) -> anyhow::Result<Self> {
        let mac_output = kms_client
            .generate_mac()
            .key_id(key_arn.clone())
            .mac_algorithm(MacAlgorithmSpec::HmacSha384)
            .message(Blob::new(epoch.to_be_bytes()))
            .send()
            .await?;

        let secret = match mac_output.mac {
            Some(mac) => mac.into_inner(),
            // the KMS documentation implies that the ciphertext and plaintext
            // fields are required, although the SDK does not model them as such
            // https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html#API_GenerateMac_ResponseSyntax
            None => anyhow::bail!("failed to retrieve the Mac from the GenerateMac operation"),
        };

        Ok(Self {
            key_arn: key_arn.clone(),
            key_epoch: epoch,
            secret,
        })
    }

    #[cfg(test)]
    pub fn test_constructor(key_arn: KeyArn, key_epoch: u64, secret: Vec<u8>) -> Self {
        Self {
            key_arn,
            key_epoch,
            secret,
        }
    }

    pub fn new_connection_psk(&self) -> Result<s2n_tls::psk::Psk, S2NError> {
        let session_name = {
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let mut session_name = [0; SESSION_NAME_LENGTH];
            rng.fill(&mut session_name)
                .map_err(|_| S2NError::application("failed to create session name".into()))?;
            session_name
        };

        let identity =
            PskIdentity::new(&session_name, self).map_err(|e| S2NError::application(e.into()))?;
        let secret = self.new_psk_secret(&session_name)?;
        Self::psk_from_parts(identity, secret)
    }

    pub fn new_psk_secret(&self, session_name: &[u8]) -> Result<Vec<u8>, S2NError> {
        let null_salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &[]);
        let pseudo_random_key = null_salt.extract(&self.secret);
        let binding = [session_name];
        let session_secret = pseudo_random_key
            .expand(&binding, hkdf::HKDF_SHA384.hmac_algorithm())
            .map_err(|_| S2NError::application("PSK secret HKDF failed".into()))?;
        let mut session_secret_bytes = vec![0; SHA384_DIGEST_SIZE];
        session_secret
            .fill(&mut session_secret_bytes)
            .map_err(|_| S2NError::application("failed to extract key material".into()))?;
        Ok(session_secret_bytes)
    }

    pub fn psk_from_parts(
        identity: PskIdentity,
        secret: Vec<u8>,
    ) -> Result<s2n_tls::psk::Psk, S2NError> {
        let identity_bytes = identity.encode_to_vec().map_err(|e| {
            S2NError::application(format!("unable to encode PSK identity: {e:?}").into())
        })?;
        let mut psk = s2n_tls::psk::Psk::builder()?;
        psk.set_hmac(s2n_tls::enums::PskHmac::SHA384)?;
        psk.set_identity(&identity_bytes)?;
        psk.set_secret(&secret)?;
        psk.build()
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) struct PskIdentity {
    version: PskVersion,
    /// the key epoch that was used to derive the daily secret
    pub key_epoch: u64,
    /// the session name used to derive session specific keys
    pub session_name: PrefixedBlob<u16>,
    /// a value indicating the KMS key arn that was used
    kms_key_binder: PrefixedBlob<u16>,
}

impl Debug for PskIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PskIdentity")
            .field("version", &self.version)
            .field("key_epoch", &self.key_epoch)
            .field("session_name", &hex::encode(self.session_name.blob()))
            .field("kms_key_binder", &hex::encode(self.kms_key_binder.blob()))
            .finish()
    }
}

impl EncodeValue for PskIdentity {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.encode_value(&self.version)?;
        buffer.encode_value(&self.key_epoch)?;
        buffer.encode_value(&self.session_name)?;
        buffer.encode_value(&self.kms_key_binder)?;
        Ok(())
    }
}

impl DecodeValue for PskIdentity {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (version, buffer) = buffer.decode_value()?;
        let (key_epoch, buffer) = buffer.decode_value()?;
        let (session_name, buffer) = buffer.decode_value()?;
        let (kms_key_binder, buffer) = buffer.decode_value()?;

        let value = Self {
            version,
            key_epoch,
            session_name,
            kms_key_binder,
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
    pub fn new(session_name: &[u8], daily_secret: &EpochSecret) -> anyhow::Result<Self> {
        let kms_key_binder = Self::kms_key_binder(session_name, daily_secret);
        let kms_key_binder = PrefixedBlob::new(kms_key_binder)?;
        let session_name = PrefixedBlob::new(session_name.to_vec())?;
        Ok(Self {
            version: PskVersion::V2,
            key_epoch: daily_secret.key_epoch,
            session_name,
            kms_key_binder,
        })
    }

    fn kms_key_binder(session_name: &[u8], daily_secret: &EpochSecret) -> Vec<u8> {
        let mut ctx = digest::Context::new(&digest::SHA384);
        ctx.update(&daily_secret.secret);
        ctx.update(session_name);
        ctx.update(daily_secret.key_arn.as_bytes());
        let kms_key_binder = ctx.finish();
        kms_key_binder.as_ref().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::digest::SHA384;
    use std::{collections::HashSet, time::Instant};

    fn test_epoch_secret() -> EpochSecret {
        EpochSecret::test_constructor(
            "arn:1234:abcd".to_owned(),
            123_456,
            b"secret material bytes".to_vec(),
        )
    }

    /// serializing and deserializing a PSK Identity should result in the same struct
    #[test]
    fn round_trip() {
        let identity = PskIdentity::new(b"a session name", &test_epoch_secret()).unwrap();
        let serialized_identity = identity.encode_to_vec().unwrap();

        let (deserialized_identity, remaining) =
            PskIdentity::decode_from(&serialized_identity).unwrap();
        assert!(remaining.is_empty());

        assert_eq!(deserialized_identity, identity);
    }

    /// Check that the KMS key binder incorporates
    /// - session name
    /// - KMS arn
    /// - epoch secret
    ///
    /// Changing any of these should change the KMS key binder
    #[test]
    fn kms_key_binder() {
        let epoch_secret = test_epoch_secret();
        let session_name = b"session name";

        let kms_binder = PskIdentity::kms_key_binder(session_name, &epoch_secret);
        let changed_session_name =
            PskIdentity::kms_key_binder(b"other session name", &epoch_secret);
        let changed_key_name = {
            let mut changed_key = test_epoch_secret();
            changed_key.key_arn = "different key name".to_owned();
            PskIdentity::kms_key_binder(session_name, &changed_key)
        };
        let changed_epoch_secret = {
            let mut changed_key = test_epoch_secret();
            changed_key.secret = b"different secret material".to_vec();
            PskIdentity::kms_key_binder(session_name, &changed_key)
        };
        let unique_binders = HashSet::from([
            kms_binder,
            changed_session_name,
            changed_key_name,
            changed_epoch_secret,
        ]);
        assert_eq!(unique_binders.len(), 4);

        assert_eq!(unique_binders.len(), 4);
    }

    /// Check the the PSK connection secret incorporates
    /// - epoch secret
    /// - session name
    ///
    /// Changing any of these should change the connection secret
    #[test]
    fn psk_secret() -> anyhow::Result<()> {
        let epoch_secret = test_epoch_secret();
        let session_name = b"session name";

        let psk_secret = epoch_secret.new_psk_secret(session_name)?;
        let changed_session_name = epoch_secret.new_psk_secret(b"different session name")?;
        let changed_epoch_secret = {
            let mut epoch_secret = test_epoch_secret();
            epoch_secret.secret = b"different secret material".to_vec();
            epoch_secret.new_psk_secret(session_name)?
        };

        let unique_secrets =
            HashSet::from([psk_secret, changed_session_name, changed_epoch_secret]);
        assert_eq!(unique_secrets.len(), 3);

        Ok(())
    }

    /// The encoded PSK Identity from the 0.0.2 version of the library was checked
    /// in. If we ever fail to deserialize this STOP! You are about to make a
    /// breaking change. You must find a way to make your change backwards
    /// compatible.
    #[test]
    fn backwards_compatibility() {
        const ENCODED_IDENTITY: &[u8] = include_bytes!("../resources/psk_identity.bin");
        const SESSION_NAME: &[u8] = b"psk session name";

        let identity = PskIdentity::new(SESSION_NAME, &test_epoch_secret()).unwrap();

        let deserialized_identity = PskIdentity::decode_from_exact(ENCODED_IDENTITY).unwrap();
        assert_eq!(deserialized_identity, identity);
    }

    /// This is a very simple benchmark checking the cost of PSK Identity derivation
    /// We use this setup because it allows us to keep the EpochSecret struct private
    ///
    /// In release mode a PSK Derivation takes ~ 292 ns.
    #[test]
    fn psk_derivation_benchmark() {
        const TRIALS: u32 = 1_000_000;
        let start = Instant::now();
        for i in 0..TRIALS {
            let _identity = PskIdentity::new(&i.to_be_bytes(), &test_epoch_secret()).unwrap();
        }
        let elapsed = start.elapsed();
        println!(
            "total time: {:?}, per derivation: {:?}",
            elapsed,
            elapsed / TRIALS
        );
    }

    /// We should avoid logging sensitive materials
    #[test]
    fn redacted_debug() {
        let secret_a = test_epoch_secret();
        let secret_b = {
            let mut secret = test_epoch_secret();
            secret.secret = b"different material".to_vec();
            secret
        };

        // these can only be equal if the secret material isn't included in the
        // debug representation
        assert_eq!(format!("{secret_a:?}"), format!("{secret_b:?}"));
    }

    /// `output_len()` isn't a const function, so we define
    /// our own constants to let us use those values in things like array sizes.
    #[test]
    fn constant_check() {
        assert_eq!(SHA384_DIGEST_SIZE, SHA384.output_len());
    }
}
