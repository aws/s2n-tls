// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::EncodeValue,
    identity::{ObfuscationKey, PskIdentity},
    psk_from_material, KeyArn, KEY_ROTATION_PERIOD, PSK_SIZE,
};
use aws_sdk_kms::Client;
use s2n_tls::{callbacks::ConnectionFuture, config::ConnectionInitializer};
use std::{
    pin::Pin,
    sync::{Arc, RwLock},
    time::Instant,
};

/// The `PskProvider` is used along with the [`PskReceiver`] to perform TLS
/// 1.3 out-of-band PSK authentication, using PSK's generated from KMS.
///
/// This struct can be enabled on a config with [`s2n_tls::config::Builder::set_connection_initializer`].
///
/// The PSK is automatically rotated every 24 hours. Any errors in this rotation
/// are logged through `tracing::error!`. Consider using something like
/// [`tracing_subscriber`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/)
/// to ensure visibility into these failures.
#[derive(Debug, Clone)]
pub struct PskProvider {
    /// The KMS client
    client: Client,
    /// The KMS key arn that will be used to generate the datakey which are
    /// used as TLS Psk's.
    kms_key_arn: Arc<KeyArn>,
    /// The key used to obfuscate the ciphertext datakey from KMS.
    ///
    /// KMS ciphertexts have observable regularities in their structure. Obfuscating
    /// the identity prevents any of that from being observable over the wire.
    obfuscation_key: Arc<ObfuscationKey>,
    /// The current Psk being set on all new connections.
    ///
    /// The lock is necessary because this is updated every 24 hours by the
    /// background updater.
    psk: Arc<RwLock<s2n_tls::psk::Psk>>,
    /// The last time the key was updated. If `None`, then a key update is in progress.
    last_update: Arc<RwLock<Option<Instant>>>,
}

impl PskProvider {
    /// Initialize a `PskProvider`.
    ///
    /// This method will call the KMS generate-data-key API to create the initial
    /// PSK that will be used for TLS connections.
    pub async fn initialize(
        client: Client,
        key: KeyArn,
        obfuscation_key: ObfuscationKey,
    ) -> anyhow::Result<Self> {
        let psk = Self::generate_psk(&client, &key, &obfuscation_key).await?;

        let value = Self {
            client: client.clone(),
            kms_key_arn: Arc::new(key),
            obfuscation_key: Arc::new(obfuscation_key),
            psk: Arc::new(RwLock::new(psk)),
            last_update: Arc::new(RwLock::new(Some(Instant::now()))),
        };
        Ok(value)
    }

    /// Check if a key update is needed. If it is, kick off a background task
    /// to call KMS and create a new PSK.
    fn maybe_trigger_key_update(&self) {
        let last_update = match *self.last_update.read().unwrap() {
            Some(update) => update,
            None => {
                // update already in progress
                return;
            }
        };

        if last_update.elapsed() > KEY_ROTATION_PERIOD {
            // because we released the lock above, we need to recheck the update
            // status after acquiring the lock.
            let mut reacquired_update = self.last_update.write().unwrap();
            if reacquired_update.is_some() {
                *reacquired_update = None;
                tokio::spawn({
                    let psk_provider = self.clone();
                    async move {
                        psk_provider.rotate_key(last_update).await;
                    }
                });
            }
        }
    }

    pub async fn rotate_key(&self, previous_update: Instant) {
        match Self::generate_psk(&self.client, &self.kms_key_arn, &self.obfuscation_key).await {
            Ok(psk) => {
                *self.psk.write().unwrap() = psk;
                *self.last_update.write().unwrap() = Some(Instant::now());
            }
            Err(e) => {
                // we failed to update the PSK. Restore the previous update and let
                // someone else try.
                tracing::error!("failed to create PSK from KMS {e}");
                *self.last_update.write().unwrap() = Some(previous_update);
            }
        }
    }

    // This method accepts owned arguments instead of `&self` so that the same
    // code can be used in the constructor as well as the background updater.
    /// Call the KMS `generate datakey` API to gather materials to be used as a TLS PSK.
    async fn generate_psk(
        client: &Client,
        key: &KeyArn,
        obfuscation_key: &ObfuscationKey,
    ) -> anyhow::Result<s2n_tls::psk::Psk> {
        let data_key = client
            .generate_data_key()
            .key_id(key.clone())
            .number_of_bytes(PSK_SIZE as i32)
            .send()
            .await
            .unwrap();

        let plaintext_datakey = data_key.plaintext().cloned().unwrap().into_inner();
        let ciphertext_datakey = data_key.ciphertext_blob().cloned().unwrap().into_inner();

        let psk_identity = PskIdentity::new(&ciphertext_datakey, obfuscation_key)?;
        let psk_identity_bytes = psk_identity.encode_to_vec()?;
        let psk = psk_from_material(&psk_identity_bytes, &plaintext_datakey)?;
        Ok(psk)
    }
}

impl ConnectionInitializer for PskProvider {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        let psk = self.psk.read().unwrap();
        connection.append_psk(&psk)?;
        self.maybe_trigger_key_update();
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{
            configs_from_callbacks, decrypt_mocks, handshake, CIPHERTEXT_DATAKEY, KMS_KEY_ARN,
            OBFUSCATION_KEY, PLAINTEXT_DATAKEY,
        },
        PskReceiver,
    };
    use aws_sdk_kms::{operation::generate_data_key::GenerateDataKeyOutput, primitives::Blob};
    use aws_smithy_mocks::{mock, mock_client};
    use std::time::Duration;

    #[tokio::test]
    async fn key_rotation() {
        const CIPHERTEXT_2: &[u8] = b"ciphertext 2";
        const PLAINTEXT_2: &[u8] = b"plaintext 2 - kuhdo8a3hdukncs4f8ay3h";
        let gdk_rule = mock!(aws_sdk_kms::Client::generate_data_key)
            .sequence()
            .output(|| {
                GenerateDataKeyOutput::builder()
                    .plaintext(Blob::new(PLAINTEXT_DATAKEY))
                    .ciphertext_blob(Blob::new(CIPHERTEXT_DATAKEY))
                    .build()
            })
            .output(|| {
                GenerateDataKeyOutput::builder()
                    .plaintext(Blob::new(PLAINTEXT_2))
                    .ciphertext_blob(Blob::new(CIPHERTEXT_2))
                    .build()
            })
            .build();
        let gdk_client = mock_client!(aws_sdk_kms, [&gdk_rule]);

        let psk_provider =
            PskProvider::initialize(gdk_client, KMS_KEY_ARN.to_string(), OBFUSCATION_KEY.clone())
                .await
                .unwrap();

        let (_decrypt_rule, decrypt_client) = decrypt_mocks();
        let psk_receiver = PskReceiver::new(
            decrypt_client,
            vec![KMS_KEY_ARN.to_owned()],
            vec![OBFUSCATION_KEY.clone()],
        );

        let last_update_handle = psk_provider.last_update.clone();
        let last_update = *last_update_handle.read().unwrap();
        let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

        // on the first handshake, no update happened
        handshake(&client_config, &server_config).await.unwrap();
        assert_eq!(last_update, last_update_handle.read().unwrap().clone());

        // "advance time" by setting last_update to the past
        let expired_time = last_update
            .unwrap()
            .checked_sub(KEY_ROTATION_PERIOD + Duration::from_secs(1))
            .unwrap();
        *last_update_handle.write().unwrap() = Some(expired_time);
        assert_eq!(gdk_rule.num_calls(), 1);

        // on the second handshake, an update is kicked off
        handshake(&client_config, &server_config).await.unwrap();
        assert!(Some(expired_time) != *last_update_handle.read().unwrap());

        // the update resulted in another generate data key call
        while last_update_handle.read().unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(gdk_rule.num_calls(), 2);
    }
}
