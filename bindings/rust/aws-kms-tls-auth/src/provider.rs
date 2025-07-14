// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::EncodeValue,
    identity::{KmsDatakey, ObfuscationKey, PskIdentity},
    psk_from_material, KeyArn, KEY_ROTATION_PERIOD, PSK_SIZE,
};
use aws_sdk_kms::Client;
use s2n_tls::{callbacks::ConnectionFuture, config::ConnectionInitializer};
use std::{
    fmt::Debug,
    pin::Pin,
    sync::{Arc, RwLock},
};
use tokio::time::Instant;

/// The `PskProvider` is used along with the [`PskReceiver`] to perform TLS
/// 1.3 out-of-band PSK authentication, using PSK's generated from KMS.
///
/// This struct can be enabled on a config with [`s2n_tls::config::Builder::set_connection_initializer`].
///
/// The PSK is automatically rotated every 24 hours. Any errors in this rotation
/// are logged through `tracing::error!`. Consider using something like
/// [`tracing_subscriber`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/)
/// to ensure visibility into these failures.
#[derive(Clone)]
pub struct PskProvider {
    /// The KMS client
    kms_client: Client,
    /// The KMS key arn that will be used to generate the datakey which are
    /// used as TLS Psk's.
    kms_key_arn: Arc<KeyArn>,
    /// The key used to obfuscate the ciphertext datakey from KMS.
    obfuscation_key: Arc<ObfuscationKey>,
    /// The current datakey being used to create the PSKs on new connections.
    ///
    /// The lock is necessary because this is updated every 24 hours by the
    /// background updater.
    datakey: Arc<RwLock<KmsDatakey>>,
    /// The last time we attempted a key update.
    ///
    /// If `None`, then a key update is in progress.
    last_update_attempt: Arc<RwLock<Option<Instant>>>,
    failure_notification: Arc<dyn Fn(anyhow::Error) + Send + Sync>,
}

impl PskProvider {
    /// Initialize a `PskProvider`.
    ///
    /// * `kms_client`: The KMS client that will be used to make generateDataKey calls.
    /// * `key`: The KeyArn which will be used in the API calls
    /// * `obfuscation_key`: The key used to obfuscate any ciphertext details over the wire.
    /// * `failure_notification`: A callback invoked if there is ever a failure
    ///   when rotating the key.
    ///
    /// This method will call the KMS generate-data-key API to create the initial
    /// PSK that will be used for TLS connections.
    ///
    /// Customers should emit metrics and alarm if there is a failure to rotate
    /// the key. If the key fails to rotate, then the PskProvider will continue
    /// using the existing key, and attempt rotation again after [`KEY_ROTATION_PERIOD`]
    /// has elapsed.
    ///
    /// The `failure_notification` implementation will depend on a customer's specific
    /// metrics/alarming configuration. As an example, if a customer is already
    /// alarming on tracing `error` events then the following might be sufficient:
    /// ```ignore
    /// PskProvider::initialize(client, key, obfuscation_key, |error| {
    ///     tracing::error!("failed to rotate key: {error}");
    /// });
    /// ```
    pub async fn initialize(
        kms_client: Client,
        key: KeyArn,
        obfuscation_key: ObfuscationKey,
        failure_notification: impl Fn(anyhow::Error) + Send + Sync + 'static,
    ) -> anyhow::Result<Self> {
        let datakey = Self::generate_psk(&kms_client, &key).await?;

        let value = Self {
            kms_client: kms_client.clone(),
            kms_key_arn: Arc::new(key),
            obfuscation_key: Arc::new(obfuscation_key),
            datakey: Arc::new(RwLock::new(datakey)),
            last_update_attempt: Arc::new(RwLock::new(Some(Instant::now()))),
            failure_notification: Arc::new(failure_notification),
        };
        Ok(value)
    }

    /// Check if a key update is needed. If it is, kick off a background task
    /// to call KMS and create a new PSK.
    fn maybe_trigger_key_update(&self) {
        let last_update = match *self.last_update_attempt.read().unwrap() {
            Some(update) => update,
            None => {
                // update already in progress
                return;
            }
        };

        if last_update.elapsed() >= KEY_ROTATION_PERIOD {
            // because we released the lock above, we need to recheck the update
            // status after acquiring the lock.
            let mut reacquired_update = self.last_update_attempt.write().unwrap();
            if reacquired_update.is_some() {
                *reacquired_update = None;
                tokio::spawn({
                    let psk_provider = self.clone();
                    async move {
                        psk_provider.rotate_key().await;
                    }
                });
            }
        }
    }

    async fn rotate_key(&self) {
        match Self::generate_psk(&self.kms_client, &self.kms_key_arn).await {
            Ok(psk) => {
                *self.datakey.write().unwrap() = psk;
            }
            Err(e) => {
                (self.failure_notification)(e);
            }
        }
        *self.last_update_attempt.write().unwrap() = Some(Instant::now());
    }

    // This method accepts owned arguments instead of `&self` so that the same
    // code can be used in the constructor as well as the background updater.
    /// Call the KMS `generate datakey` API to gather materials to be used as a TLS PSK.
    async fn generate_psk(client: &Client, key: &KeyArn) -> anyhow::Result<KmsDatakey> {
        let data_key = client
            .generate_data_key()
            .key_id(key.clone())
            .number_of_bytes(PSK_SIZE as i32)
            .send()
            .await?;

        match (data_key.plaintext, data_key.ciphertext_blob) {
            (Some(plaintext), Some(ciphertext)) => Ok(KmsDatakey {
                ciphertext: ciphertext.into_inner(),
                plaintext: plaintext.into_inner(),
            }),
            // the KMS documentation implies that the ciphertext and plaintext
            // fields are required, although the SDK does not model them as such
            // https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html#API_GenerateDataKey_ResponseElements
            _ => anyhow::bail!("failed to retrieve ciphertext or plaintext from GDK"),
        }
    }
}

impl ConnectionInitializer for PskProvider {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        let psk = {
            let datakey = self.datakey.read().unwrap();

            let psk_identity =
                PskIdentity::new(&datakey.ciphertext, &self.obfuscation_key).unwrap();
            let psk_identity_bytes = psk_identity
                .encode_to_vec()
                .map_err(|e| s2n_tls::error::Error::application(e.into()))?;
            psk_from_material(&psk_identity_bytes, &datakey.plaintext)?
        };
        connection.append_psk(&psk)?;
        self.maybe_trigger_key_update();
        Ok(None)
    }
}

impl Debug for PskProvider {
    // we use a custom Debug implementation because the failure notification doesn't
    // implement debug
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PskProvider")
            .field("kms_client", &self.kms_client)
            .field("kms_key_arn", &self.kms_key_arn)
            .field("obfuscation_key", &self.obfuscation_key)
            .field("psk", &self.datakey)
            .field("last_update_attempt", &self.last_update_attempt)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        psk_parser::retrieve_psk_identities,
        test_utils::{
            configs_from_callbacks, decrypt_mocks, handshake, test_psk_provider, DECRYPT_OUTPUT_A,
            DECRYPT_OUTPUT_B, GDK_OUTPUT_A, GDK_OUTPUT_B, KMS_KEY_ARN, OBFUSCATION_KEY,
        },
        DecodeValue, PskReceiver,
    };
    use aws_sdk_kms::{
        operation::generate_data_key::GenerateDataKeyError,
        types::error::builders::KeyUnavailableExceptionBuilder,
    };
    use aws_smithy_mocks::{mock, mock_client};
    use std::{
        collections::HashSet,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    // the error doesn't implement clone, so we have to use this test helper
    fn gdk_error() -> GenerateDataKeyError {
        GenerateDataKeyError::KeyUnavailableException(
            KeyUnavailableExceptionBuilder::default().build(),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn key_rotation() {
        let gdk_rule = mock!(aws_sdk_kms::Client::generate_data_key)
            .sequence()
            .output(|| GDK_OUTPUT_A.clone())
            .output(|| GDK_OUTPUT_B.clone())
            .build();
        let gdk_client = mock_client!(aws_sdk_kms, [&gdk_rule]);

        let psk_provider = PskProvider::initialize(
            gdk_client,
            KMS_KEY_ARN.to_string(),
            OBFUSCATION_KEY.clone(),
            |_| {},
        )
        .await
        .unwrap();

        let (_decrypt_rule, decrypt_client) = decrypt_mocks();
        let psk_receiver = PskReceiver::new(
            decrypt_client,
            vec![KMS_KEY_ARN.to_owned()],
            vec![OBFUSCATION_KEY.clone()],
        );

        let last_update_handle = psk_provider.last_update_attempt.clone();
        let creation_time = Instant::now();
        let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

        tokio::time::advance(Duration::from_secs(1)).await;

        // on the first handshake, no update happened
        handshake(&client_config, &server_config).await.unwrap();
        assert_eq!(*last_update_handle.read().unwrap(), Some(creation_time));

        tokio::time::advance(KEY_ROTATION_PERIOD).await;

        // on the second handshake, an update is kicked off
        assert_eq!(gdk_rule.num_calls(), 1);
        handshake(&client_config, &server_config).await.unwrap();

        // the update resulted in another generate data key call
        while last_update_handle.read().unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(*last_update_handle.read().unwrap(), Some(Instant::now()));
        assert_eq!(gdk_rule.num_calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn failure_notification() {
        // configure a PSK provider which will successfully generate the initial
        // data key, fail twice, then succeed. Errors should increment the AtomicU64
        // error handle.
        let (psk_provider, gdk_rule, error_handle) = {
            let gdk_rule = mock!(aws_sdk_kms::Client::generate_data_key)
                .sequence()
                .output(|| GDK_OUTPUT_A.clone())
                .error(gdk_error)
                .error(gdk_error)
                .output(|| GDK_OUTPUT_B.clone())
                .build();
            let gdk_client = mock_client!(aws_sdk_kms, [&gdk_rule]);

            let error_count = Arc::new(AtomicU64::default());
            let error_handle = Arc::clone(&error_count);
            let psk_provider = PskProvider::initialize(
                gdk_client,
                KMS_KEY_ARN.to_string(),
                OBFUSCATION_KEY.clone(),
                move |_| {
                    error_count.fetch_add(1, Ordering::Relaxed);
                },
            )
            .await
            .unwrap();

            (psk_provider, gdk_rule, error_handle)
        };

        // configure a PSK receiver capable of decrypting the two datakeys that
        // the provider will generate.
        let (psk_receiver, decrypt_rule) = {
            let decrypt_rule = mock!(aws_sdk_kms::Client::decrypt)
                .sequence()
                .output(|| DECRYPT_OUTPUT_A.clone())
                .output(|| DECRYPT_OUTPUT_B.clone())
                .build();
            let decrypt_client = mock_client!(aws_sdk_kms, [&decrypt_rule]);
            let psk_receiver = PskReceiver::new(
                decrypt_client,
                vec![KMS_KEY_ARN.to_owned()],
                vec![OBFUSCATION_KEY.clone()],
            );
            (psk_receiver, decrypt_rule)
        };

        let last_update_handle = psk_provider.last_update_attempt.clone();
        let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

        // Period 0: handshake is successful, using the initial PSK
        {
            handshake(&client_config, &server_config).await.unwrap();
            assert_eq!(error_handle.load(Ordering::Relaxed), 0);
            assert_eq!(decrypt_rule.num_calls(), 1);
        }

        tokio::time::advance(KEY_ROTATION_PERIOD).await;

        // Period 1: GDK fails, and is logged
        {
            handshake(&client_config, &server_config).await.unwrap();
            while last_update_handle.read().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(error_handle.load(Ordering::Relaxed), 1);
            assert_eq!(*last_update_handle.read().unwrap(), Some(Instant::now()));
            assert_eq!(gdk_rule.num_calls(), 2);
        }

        tokio::time::advance(Duration::from_secs(1)).await;

        // Period 1+: GDK is not retried until KEY_ROTATION_PERIOD has elapsed
        {
            handshake(&client_config, &server_config).await.unwrap();
            while last_update_handle.read().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(error_handle.load(Ordering::Relaxed), 1);
            assert_eq!(gdk_rule.num_calls(), 2);
        }

        tokio::time::advance(KEY_ROTATION_PERIOD).await;

        // Period 2: GDK fails, and is logged. The server is successfully handshaking
        // with the initial PSK.
        {
            handshake(&client_config, &server_config).await.unwrap();
            while last_update_handle.read().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(*last_update_handle.read().unwrap(), Some(Instant::now()));
            assert_eq!(error_handle.load(Ordering::Relaxed), 2);
            assert_eq!(decrypt_rule.num_calls(), 1);
        }

        tokio::time::advance(KEY_ROTATION_PERIOD).await;

        // Period 3: GDK Succeeds, although it is not used for the current handshake
        {
            handshake(&client_config, &server_config).await.unwrap();
            while last_update_handle.read().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(error_handle.load(Ordering::Relaxed), 2);
            assert_eq!(decrypt_rule.num_calls(), 1);
            assert_eq!(gdk_rule.num_calls(), 4);
        }

        // Period 3+: The next handshake uses the new PSK
        {
            handshake(&client_config, &server_config).await.unwrap();
            while last_update_handle.read().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(error_handle.load(Ordering::Relaxed), 2);
            assert_eq!(decrypt_rule.num_calls(), 2);
        }
    }

    /// The PSK Identity should be unique per-connection because of the randomized
    /// nonce
    #[tokio::test]
    async fn per_connection_psk_identity() -> anyhow::Result<()> {
        const NUM_HANDSHAKES: usize = 5;
        let psk_provider = test_psk_provider().await;
        let (_decrypt_rule, decrypt_client) = decrypt_mocks();
        let psk_receiver = PskReceiver::new(
            decrypt_client,
            vec![KMS_KEY_ARN.to_owned()],
            vec![OBFUSCATION_KEY.clone()],
        );

        let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);
        let mut identities = Vec::new();
        for _ in 0..NUM_HANDSHAKES {
            let server = handshake(&client_config, &server_config).await.unwrap();
            let client_hello = server.as_ref().client_hello()?;
            let psks = retrieve_psk_identities(client_hello)?;
            identities.push(psks);
        }

        let unique_identities: HashSet<PskIdentity> = identities
            .into_iter()
            .map(|psk| {
                assert_eq!(psk.list().len(), 1);
                psk.list().first().unwrap().clone().identity.take_blob()
            })
            .map(|blob| PskIdentity::decode_from_exact(&blob).unwrap())
            .collect();

        // all of the psk_identities should be unique (different nonces)
        assert_eq!(unique_identities.len(), NUM_HANDSHAKES);

        let expected_ciphertext = unique_identities
            .iter()
            .next()
            .unwrap()
            .deobfuscate_datakey(&[OBFUSCATION_KEY.clone()])
            .unwrap();
        let all_have_expected_ciphertext = unique_identities
            .into_iter()
            .map(|id| id.deobfuscate_datakey(&[OBFUSCATION_KEY.clone()]).unwrap())
            .all(|ciphertext| ciphertext == expected_ciphertext);
        assert!(all_have_expected_ciphertext);

        Ok(())
    }
}
