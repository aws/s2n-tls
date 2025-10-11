// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::DecodeValue,
    epoch_schedule,
    psk_derivation::{EpochSecret, PskIdentity},
    psk_parser::retrieve_psk_identities,
    KeyArn, ONE_HOUR,
};
use aws_sdk_kms::Client;
use s2n_tls::{
    callbacks::{ClientHelloCallback, ConnectionFuture},
    error::Error as S2NError,
};
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};

#[derive(Debug)]
struct ReceiverSecrets {
    smoothing_factor: Duration,
    pub trusted_key_arns: Vec<KeyArn>,
    pub epoch_secrets: RwLock<HashMap<u64, HashMap<KeyArn, EpochSecret>>>,
}

impl ReceiverSecrets {
    fn new(trusted_key_arns: Vec<KeyArn>) -> Self {
        Self {
            smoothing_factor: epoch_schedule::smoothing_factor(),
            trusted_key_arns,
            epoch_secrets: Default::default(),
        }
    }

    /// Given a decoded client_identity, try to find an EpochSecret that was used
    /// to produce it. This requires generating the corresponding PskIdentity for
    /// all of the trusted KMS keys.
    fn find_match(&self, client_identity: PskIdentity) -> anyhow::Result<s2n_tls::psk::Psk> {
        let read_lock = self.epoch_secrets.read().unwrap();
        let key_map = match read_lock.get(&client_identity.key_epoch) {
            Some(key_map) => key_map,
            None => anyhow::bail!(
                "no keys found for client epoch {}",
                client_identity.key_epoch
            ),
        };

        for epoch_secret in key_map.values() {
            let psk_identity = PskIdentity::new(client_identity.session_name.blob(), epoch_secret)?;
            if psk_identity == client_identity {
                let psk_secret =
                    epoch_secret.new_psk_secret(client_identity.session_name.blob())?;
                return EpochSecret::psk_from_parts(psk_identity, psk_secret)
                    .map_err(|e| anyhow::anyhow!("failed to construct psk {e}"));
            }
        }

        anyhow::bail!(
            "no matching kms binder found for session {}",
            hex::encode(client_identity.session_name.blob())
        );
    }

    fn insert_secret(&self, epoch_secret: EpochSecret) {
        self.epoch_secrets
            .write()
            .unwrap()
            .entry(epoch_secret.key_epoch)
            .or_default()
            .insert(epoch_secret.key_arn.clone(), epoch_secret);
    }

    /// Return a list of all the (epoch, key_arn) EpochSecrets that are available
    fn available_secrets(&self) -> Vec<(u64, KeyArn)> {
        self.epoch_secrets
            .read()
            .unwrap()
            .iter()
            .flat_map(|(epoch, arn_map)| arn_map.keys().map(|key_arn| (*epoch, key_arn.clone())))
            .collect()
    }

    fn newest_available_epoch(&self) -> Option<u64> {
        self.epoch_secrets.read().unwrap().keys().max().cloned()
    }

    async fn fetch_secrets(
        &self,
        kms_client: &Client,
        current_epoch: u64,
        failure_notification: &(dyn Fn(anyhow::Error) + Send + Sync + 'static),
    ) -> Result<Duration, Duration> {
        // fetch all keys that aren't already available
        // This will almost always just fetch `this_epoch + 2`, unless key
        // generation has failed for several days
        let mut fetch_failed = false;
        let mut to_fetch: Vec<(u64, KeyArn)> = {
            [
                current_epoch - 1,
                current_epoch,
                current_epoch + 1,
                current_epoch + 2,
            ]
            .iter()
            .flat_map(|epoch| {
                self.trusted_key_arns
                    .iter()
                    .cloned()
                    .map(|arn| (*epoch, arn))
            })
            .collect()
        };

        let available: Vec<(u64, KeyArn)> = self.available_secrets();
        to_fetch.retain(|epoch| !available.contains(epoch));

        for (epoch, key_arn) in to_fetch {
            match EpochSecret::fetch_epoch_secret(kms_client, &key_arn, epoch).await {
                Ok(epoch_secret) => {
                    tracing::debug!("fetched secret for epoch {epoch} from {key_arn} ");
                    self.insert_secret(epoch_secret);
                }
                Err(e) => {
                    fetch_failed = true;
                    tracing::error!(
                        "failed to fetch secret for epoch {epoch} from {key_arn}: {e:?}"
                    );
                    failure_notification(anyhow::anyhow!("failed to fetch {key_arn}").context(e));
                }
            }
        }

        if fetch_failed {
            return Err(ONE_HOUR);
        }

        let sleep_duration = self.newest_available_epoch().and_then(|fetch_epoch| {
            epoch_schedule::until_fetch(fetch_epoch + 1, self.smoothing_factor)
        });
        match sleep_duration {
            Some(duration) => Ok(duration),
            None => Err(ONE_HOUR),
        }
    }

    /// Drop all of the unneeded secrets.
    ///
    /// If the current epoch is `n`, any key from epoch `n - 2` or earlier will
    /// be dropped.
    fn cleanup_old_secrets(&self, current_epoch: u64) {
        self.epoch_secrets
            .write()
            .unwrap()
            .retain(|epoch, _arn_map| *epoch >= current_epoch - 1);
    }

    /// The is the entry point for periodic updates of the secret state.
    ///
    /// This will fetch any new secrets that are needed, and clean up old secrets.
    async fn poll_update(
        &self,
        kms_client: &Client,
        current_epoch: u64,
        failure_notification: &(dyn Fn(anyhow::Error) + Send + Sync + 'static),
    ) -> Result<Duration, Duration> {
        let sleep_duration = self
            .fetch_secrets(kms_client, current_epoch, failure_notification)
            .await;
        self.cleanup_old_secrets(current_epoch);
        sleep_duration
    }
}

/// The `PskReceiver` is used along with the [`PskProvider`] to perform TLS
/// 1.3 out-of-band PSK authentication, using PSK's generated from KMS.
///
/// This struct can be enabled on a config with [`s2n_tls::config::Builder::set_client_hello_callback`].
#[derive(Debug, Clone)]
pub struct PskReceiver {
    secrets: Arc<ReceiverSecrets>,
}

impl PskReceiver {
    /// Create a new PskReceiver.
    ///
    /// This will receive the ciphertext datakey identities from a TLS client hello,
    /// then decrypt them using KMS. This establishes a mutually authenticated TLS
    /// handshake between parties with IAM permissions to generate and decrypt data keys
    ///
    /// * `kms_client`: The KMS Client that will be used for the decrypt calls
    ///
    /// * `trusted_key_arns`: The list of KMS KeyArns that the PskReceiver will
    ///   accept PSKs from. Applications should avoid trusting large (1000+) numbers
    ///   of KMS keys, because the PskReceiver has to do brute force linear matching
    ///   to find the KMS key that was used for a client identity. This costs ~ 300ns
    ///   per trusted key, and thus is negligible for small amounts of trusted keys.
    pub async fn initialize(
        kms_client: Client,
        trusted_key_arns: Vec<KeyArn>,
        failure_notification: impl Fn(anyhow::Error) + Send + Sync + 'static,
    ) -> anyhow::Result<Self> {
        let secret_state = Arc::new(ReceiverSecrets::new(trusted_key_arns.clone()));
        let current_epoch = epoch_schedule::current_epoch();

        let update = secret_state
            .fetch_secrets(&kms_client, current_epoch, &failure_notification)
            .await;
        if update.is_err() {
            anyhow::bail!("failed to fetch keys during startup");
        }

        // spawn the fetcher
        let secret_handle = Arc::clone(&secret_state);
        tokio::spawn(async move {
            loop {
                let this_epoch = epoch_schedule::current_epoch();
                let sleep_duration = secret_handle
                    .fetch_secrets(&kms_client, this_epoch, &failure_notification)
                    .await;
                secret_handle.cleanup_old_secrets(this_epoch);

                let sleep_duration = match sleep_duration {
                    Ok(d) => d,
                    Err(d) => d,
                };
                tracing::debug!("sleeping for {sleep_duration:?}");
                tokio::time::sleep(sleep_duration).await;
            }
        });

        Ok(Self {
            secrets: secret_state,
        })
    }
}

impl ClientHelloCallback for PskReceiver {
    fn on_client_hello(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        // parse the identity list from the client hello
        let client_hello = connection.client_hello()?;
        let identities = match retrieve_psk_identities(client_hello) {
            Ok(identities) => identities,
            Err(e) => {
                return Err(s2n_tls::error::Error::application(e.into()));
            }
        };

        // extract the identity bytes from the first PSK entry. We assume that we
        // are talking to a PskProvider, so we don't look at any additional entries.
        let psk_identity = match identities.list().first() {
            Some(id) => id.identity.blob(),
            None => {
                return Err(s2n_tls::error::Error::application(
                    "identities list was zero-length".into(),
                ))
            }
        };

        // parse the identity bytes to a PskIdentity
        let client_identity = PskIdentity::decode_from_exact(psk_identity)
            .map_err(|e| s2n_tls::error::Error::application(e.into()))?;
        println!("server received: {client_identity:?}");

        let psk = self
            .secrets
            .find_match(client_identity)
            .map_err(|e| S2NError::application(e.into()))?;
        connection.append_psk(&psk)?;
        Ok(None)
    }
}

#[cfg(test)]
mod secret_state_tests {
    use crate::{
        epoch_schedule::{self},
        psk_derivation::{EpochSecret, PskIdentity},
        receiver::ReceiverSecrets,
        test_utils::{self, mocked_kms_client, KMS_KEY_ARN_A, KMS_KEY_ARN_B},
        PskReceiver,
    };
    use aws_sdk_kms::{
        operation::generate_mac::{GenerateMacError, GenerateMacOutput},
        primitives::Blob,
        Client,
    };
    use aws_smithy_mocks::{mock, mock_client};
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    #[test]
    fn key_insertion() {
        let secret_state = ReceiverSecrets::new(vec![]);
        assert!(secret_state.epoch_secrets.read().unwrap().is_empty());
        let secret_a = EpochSecret {
            key_arn: "arn:1235:abc".to_owned(),
            key_epoch: 31456,
            secret: b"some secret".to_vec(),
        };
        let secret_b = EpochSecret {
            key_arn: "arn:1235:abd".to_owned(),
            key_epoch: 31457,
            secret: b"some secret".to_vec(),
        };

        {
            secret_state.insert_secret(secret_a.clone());
            let epoch_map = secret_state.epoch_secrets.read().unwrap();
            assert_eq!(epoch_map.len(), 1);
            assert_eq!(epoch_map.get(&secret_a.key_epoch).unwrap().len(), 1);
            assert_eq!(
                epoch_map
                    .get(&secret_a.key_epoch)
                    .unwrap()
                    .get(&secret_a.key_arn),
                Some(&secret_a)
            );
        }

        {
            secret_state.insert_secret(secret_b.clone());
            let epoch_map = secret_state.epoch_secrets.read().unwrap();
            assert_eq!(epoch_map.len(), 2);
            assert_eq!(epoch_map.get(&secret_b.key_epoch).unwrap().len(), 1);
            assert_eq!(
                epoch_map
                    .get(&secret_b.key_epoch)
                    .unwrap()
                    .get(&secret_b.key_arn),
                Some(&secret_b)
            );
        }

        let available = secret_state.available_secrets();
        assert!(available.contains(&(secret_a.key_epoch, secret_a.key_arn)));
        assert!(available.contains(&(secret_b.key_epoch, secret_b.key_arn)));
        assert_eq!(available.len(), 2);
    }

    #[test]
    fn psk_matching() {
        let secret_state = ReceiverSecrets::new(vec!["arn:1235:abc".to_owned()]);
        let epoch_secret = EpochSecret {
            key_arn: "arn:1235:abc".to_owned(),
            key_epoch: 31456,
            secret: b"some secret".to_vec(),
        };
        secret_state.insert_secret(epoch_secret.clone());

        // matching PSK identity
        let session_name = b"test_session".to_vec();
        let psk_identity = PskIdentity::new(&session_name, &epoch_secret).unwrap();
        secret_state.find_match(psk_identity.clone()).unwrap();

        // non-matching PSK identity - right epoch, wrong key
        let other_secret = EpochSecret {
            key_arn: "arn:1235:different".to_owned(),
            key_epoch: 31456,
            secret: b"some secret".to_vec(),
        };
        let different_identity = PskIdentity::new(&session_name, &other_secret).unwrap();
        let error = secret_state.find_match(different_identity).unwrap_err();
        assert!(error
            .to_string()
            .contains("no matching kms binder found for session"));

        // non-matching PSK identity - wrong epoch
        let non_existent_epoch_secret = EpochSecret {
            key_arn: "arn:1235:abc".to_owned(),
            key_epoch: 99999,
            secret: b"some secret".to_vec(),
        };
        let non_existent_identity =
            PskIdentity::new(&session_name, &non_existent_epoch_secret).unwrap();
        let error = secret_state.find_match(non_existent_identity).unwrap_err();
        assert_eq!(error.to_string(), "no keys found for client epoch 99999");
    }

    #[tokio::test]
    async fn initialization_fetches_keys() {
        let kms_client = test_utils::mocked_kms_client();
        let trusted_key_arns = vec![KMS_KEY_ARN_A.to_owned()];
        let receiver = PskReceiver::initialize(kms_client, trusted_key_arns, |_| {})
            .await
            .unwrap();
        assert_eq!(receiver.secrets.available_secrets().len(), 4);

        let kms_client = test_utils::mocked_kms_client();
        let trusted_key_arns = vec![KMS_KEY_ARN_A.to_owned(), KMS_KEY_ARN_B.to_owned()];
        let receiver = PskReceiver::initialize(kms_client, trusted_key_arns, |_| {})
            .await
            .unwrap();
        assert_eq!(receiver.secrets.available_secrets().len(), 8);
    }

    #[tokio::test]
    async fn poll_update() -> Result<(), Duration> {
        let psk_provider =
            PskReceiver::initialize(mocked_kms_client(), vec![KMS_KEY_ARN_A.to_owned()], |_| {})
                .await
                .unwrap();
        let mut this_epoch = epoch_schedule::current_epoch();
        let client = mocked_kms_client();
        let secret_state = psk_provider.secrets;

        secret_state
            .poll_update(&client, this_epoch, &|_| {})
            .await?;
        let available = secret_state.available_secrets();
        assert_eq!(available.len(), 4);
        assert!(available.contains(&(this_epoch - 1, KMS_KEY_ARN_A.to_owned())));
        assert!(available.contains(&(this_epoch, KMS_KEY_ARN_A.to_owned())));
        assert!(available.contains(&(this_epoch + 1, KMS_KEY_ARN_A.to_owned())));
        assert!(available.contains(&(this_epoch + 2, KMS_KEY_ARN_A.to_owned())));

        // idempotent if the time hasn't changed
        secret_state
            .poll_update(&client, this_epoch, &|_| {})
            .await?;
        assert_eq!(secret_state.available_secrets(), available);

        this_epoch += 1;
        // when time advances, we
        // 1. fetch a new secret
        // 2. rotate the current one
        // 3. drop the old one
        secret_state
            .poll_update(&client, this_epoch, &|_| {})
            .await?;
        let available = secret_state.available_secrets();
        assert_eq!(available.len(), 4);
        assert!(available.contains(&(this_epoch - 1, KMS_KEY_ARN_A.to_owned())));
        assert!(available.contains(&(this_epoch, KMS_KEY_ARN_A.to_owned())));
        assert!(available.contains(&(this_epoch + 1, KMS_KEY_ARN_A.to_owned())));
        assert!(available.contains(&(this_epoch + 2, KMS_KEY_ARN_A.to_owned())));

        this_epoch += 2;
        // time skips are gracefully handled
        secret_state
            .poll_update(&client, this_epoch, &|_| {})
            .await?;
        let available = secret_state.available_secrets();
        assert_eq!(available.len(), 4);
        assert!(available.contains(&(this_epoch - 1, KMS_KEY_ARN_A.to_owned())));
        assert!(available.contains(&(this_epoch, KMS_KEY_ARN_A.to_owned())));
        assert!(available.contains(&(this_epoch + 1, KMS_KEY_ARN_A.to_owned())));
        assert!(available.contains(&(this_epoch + 2, KMS_KEY_ARN_A.to_owned())));
        Ok(())
    }

    #[tokio::test]
    async fn poll_update_with_failure() {
        let error_count = Arc::new(AtomicUsize::new(0));
        let notification_fn = {
            let error_count = Arc::clone(&error_count);
            move |_: anyhow::Error| {
                error_count.fetch_add(1, Ordering::SeqCst);
            }
        };

        let rule = mock!(Client::generate_mac)
            .sequence()
            .output(|| {
                GenerateMacOutput::builder()
                    .mac(Blob::new(b"mock_mac_output".to_vec()))
                    .build()
            })
            .times(5)
            .error(|| GenerateMacError::unhandled("MockedFailure"))
            .output(|| {
                GenerateMacOutput::builder()
                    .mac(Blob::new(b"mock_mac_output".to_vec()))
                    .build()
            })
            .build();
        let kms_client = mock_client!(aws_sdk_kms, [&rule]);

        let psk_receiver = PskReceiver::initialize(
            kms_client.clone(),
            vec![KMS_KEY_ARN_A.to_owned()],
            notification_fn.clone(),
        )
        .await
        .unwrap();
        assert_eq!(rule.num_calls(), 4);
        let current_epoch = epoch_schedule::current_epoch();

        assert_eq!(error_count.load(Ordering::SeqCst), 0);
        psk_receiver
            .secrets
            .poll_update(&kms_client, current_epoch + 1, &notification_fn)
            .await
            .unwrap();
        assert_eq!(rule.num_calls(), 5);

        assert_eq!(psk_receiver.secrets.available_secrets().len(), 4);
        psk_receiver
            .secrets
            .poll_update(&kms_client, current_epoch + 2, &notification_fn)
            .await
            .unwrap_err();
        assert_eq!(psk_receiver.secrets.available_secrets().len(), 3);
        assert_eq!(rule.num_calls(), 6);
        assert_eq!(error_count.load(Ordering::SeqCst), 1);

        psk_receiver
            .secrets
            .poll_update(&kms_client, current_epoch + 2, &notification_fn)
            .await
            .unwrap();
        assert_eq!(psk_receiver.secrets.available_secrets().len(), 4);
    }

    #[tokio::test]
    async fn initialize_fails_with_invalid_kms() {
        use aws_smithy_mocks::{mock, mock_client, RuleMode};

        // Create a mock KMS client that always fails
        let fail_rule = mock!(Client::generate_mac).then_error(|| {
            aws_sdk_kms::operation::generate_mac::GenerateMacError::unhandled("MockedFailure")
        });

        let kms_client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, [&fail_rule]);

        // Initialize should fail because all KMS calls fail
        let result =
            PskReceiver::initialize(kms_client, vec![KMS_KEY_ARN_A.to_owned()], |_| {}).await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to fetch keys during startup"));
    }
}
