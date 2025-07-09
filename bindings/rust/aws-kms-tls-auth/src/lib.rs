// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The KMS TLS PSK Provider provides a way to get a mutually authenticated TLS
//! connection using IAM credentials, KMS, and the external PSK feature of TLS 1.3.
//!
//! The client must have IAM credentials that allow `generate-datakey` API calls
//! for some KMS Key.
//!
//! The server must have IAM credentials that allow `decrypt` calls.
//!
//! ## Generate Data Key
//! The client first calls generate data key. The plaintext datakey is used as the
//! PSK secret, and is the input for [`s2n_tls::psk::Builder::set_secret`]. The
//! ciphertext datakey is set as the PSK identity (sort of, see PSK Identity section).
//!
//! ## Decrypt
//! The client then connects to the server, sending the PSK as part of its client
//! hello. The server then retrieves the PSK identity (ciphertext datakey) from the
//! client hello and calls the KMS decrypt API to retrieve the plaintext datakey.
//!
//! At this point it can construct the same PSK that the client used, so the handshake
//! is able to continue and complete successfully.
//!
//! ## Caching
//! The server component [`KmsPskReceiver`] will cache successfully decrypted ciphertexts.
//! This means that the first handshake from a new client will result in a network
//! call to KMS, but future handshakes from that client will be able to retrieve
//! the plaintext datakey from memory.
//!
//! Note that this cache is bounded to a size of [`MAXIMUM_KEY_CACHE_SIZE`].
//!
//! ## Rotation
//! The client component [`KmsPskProvider`] will automatically rotate the PSK. This
//! is controlled by the [`KEY_ROTATION_PERIOD`] which is currently 24 hours.
//!
//! ## PSK Identity
//! The ciphertext datakey is not directly used as the PSK identity. KMS ciphertexts
//! have observable regularities, so we first obfuscate the ciphertext using the
//! provided obfuscation key.
//!
//! ## Deployment Concerns
//! The obfuscation key that the [`KmsPskProvider`] is configured with must also
//! be supplied to the [`KmsPskReceiver`]. Otherwise handshakes will fail.
//!
//! The KMS Key ARN that the [`KmsPskProvider`] is configured with must be supplied
//! to the [`KmsPskReceiver`]. Otherwise handshakes will fail.
//!
//! Note that the [`KmsPskReceiver`] supports lists for both of these items, so
//! zero-downtime migrations are possible. _Example_: if the client fleet wanted
//! to switch from Key A to Key B it would go through the following stages
//! 1. client -> [A], server -> [A]
//! 2. client -> [A], server -> [A, B]
//! 3. client -> [A, B], server -> [A, B]
//! 4. client ->    [B], server -> [A, B]
//! 5. client ->    [B], server ->    [B]

mod client_hello_parser;
mod codec;
mod identity;
mod prefixed_list;
mod provider;
mod receiver;
#[cfg(test)]
pub(crate) mod test_utils;

use s2n_tls::error::Error as S2NError;
use std::time::Duration;

pub type KeyArn = String;
pub use identity::ObfuscationKey;
pub use provider::KmsPskProvider;
pub use receiver::KmsPskReceiver;

// We have "pub" use statement so these can be fuzz tested
pub use client_hello_parser::{ClientHello, PresharedKeyClientHello};
pub use codec::DecodeValue;

const MAXIMUM_KEY_CACHE_SIZE: usize = 100_000;
const PSK_SIZE: usize = 32;
const AES_256_GCM_KEY_LEN: usize = 32;
const AES_256_GCM_NONCE_LEN: usize = 12;
/// The key is automatically rotated every period. Currently 24 hours.
const KEY_ROTATION_PERIOD: Duration = Duration::from_secs(3_600 * 24);

fn psk_from_material(identity: &[u8], secret: &[u8]) -> Result<s2n_tls::psk::Psk, S2NError> {
    let mut psk = s2n_tls::psk::Psk::builder()?;
    psk.set_hmac(s2n_tls::enums::PskHmac::SHA384)?;
    psk.set_identity(identity)?;
    psk.set_secret(secret)?;
    psk.build()
}

#[cfg(test)]
mod tests {
    use crate::{AES_256_GCM_KEY_LEN, AES_256_GCM_NONCE_LEN};
    use aws_lc_rs::aead::AES_256_GCM;

    /// `key_len()` and `nonce_len()` aren't const functions, so we define
    /// our own constants to let us use those values in things like array sizes.
    #[test]
    fn constant_check() {
        assert_eq!(AES_256_GCM_KEY_LEN, AES_256_GCM.key_len());
        assert_eq!(AES_256_GCM_NONCE_LEN, AES_256_GCM.nonce_len());
    }
}

#[cfg(feature = "test-network")]
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::{
        identity::ObfuscationKey,
        test_utils::{configs_from_callbacks, handshake},
        KmsPskProvider, KmsPskReceiver,
    };
    use aws_config::Region;
    use aws_sdk_kms::Client;

    pub async fn existing_kms_key(client: &Client) -> Option<KeyArn> {
        let output = client.list_keys().send().await.unwrap();
        let key = output.keys().first();
        key.map(|key| key.key_arn().unwrap().to_string())
    }

    async fn create_kms_key(client: &Client) -> KeyArn {
        let resp = client.create_key().send().await.unwrap();
        resp.key_metadata
            .as_ref()
            .unwrap()
            .arn()
            .unwrap()
            .to_string()
    }

    pub async fn get_kms_key(client: &Client) -> KeyArn {
        if let Some(key) = existing_kms_key(client).await {
            key
        } else {
            create_kms_key(client).await
        }
    }

    pub async fn test_kms_client() -> Client {
        let shared_config = aws_config::from_env()
            .region(Region::new("us-west-2"))
            .load()
            .await;
        Client::new(&shared_config)
    }

    /// sanity check for our testing environment
    #[tokio::test]
    async fn retrieve_key() {
        let client = test_kms_client().await;
        let key_arn = existing_kms_key(&client).await;
        assert!(key_arn.is_some());
    }

    #[tokio::test]
    async fn network_kms_integ_test() -> Result<(), s2n_tls::error::Error> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::level_filters::LevelFilter::INFO)
            .init();
        let obfuscation_key = ObfuscationKey::random_test_key();

        let client = test_kms_client().await;
        let key_arn = get_kms_key(&client).await;

        let client_psk_provider =
            KmsPskProvider::initialize(client.clone(), key_arn.clone(), obfuscation_key.clone())
                .await
                .unwrap();

        let server_psk_receiver =
            KmsPskReceiver::new(client.clone(), vec![key_arn], vec![obfuscation_key]);

        let (client_config, server_config) =
            configs_from_callbacks(client_psk_provider, server_psk_receiver);

        // one handshake for the decrypt code path, another for the
        // cached code path
        handshake(&client_config, &server_config).await.unwrap();
        handshake(&client_config, &server_config).await.unwrap();

        Ok(())
    }
}
