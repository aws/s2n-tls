#![allow(dead_code)]
// allow dead code for piece-wise commits

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The KMS TLS PSK Provider provides a way to get a mutually authenticated TLS
//! connection using IAM credentials, KMS, and the external PSK feature of TLS 1.3.
//!
//! # Design
//!
//! `aws-kms-tls-auth` allows a fleet of instances to mutually authenticate each
//! other. You will configured a single [KMS HMAC Key](https://docs.aws.amazon.com/kms/latest/developerguide/hmac.html)
//! with a SHA384 signing spec and grant all of the instances IAM permissions to
//! call `kms:GenerateMAC` on the KMS key. Clients and servers are considered
//! interchangeable.
//!
//! Instances will call `kms:GenerateMAC(days_since_unix_epoch)` to obtain a secret
//! that is shared across the fleet. This is referred to as the `epoch_secret`.
//! This secret will rotate daily.
//!
//! For each new connection, the instance will generate a nonce (`session_name`)
//! and use that along with the `epoch_secret` to derive a connection-specific secret.
//! This unique secret will then be used for RFC-standard, TLS 1.3 PSK authentication
//! (PSK with (EC)DHE handshake mode).
//!
//! The authenticated identity of a peer is “the peer has IAM permissions to call
//! `kms:GenerateMAC` on the trusted KMS key”.
//!
//! ## Deployment Concerns
//!
//! The KMS Key ARN that the [`PskProvider`] is configured with must be supplied
//! to the [`PskReceiver`]. Otherwise handshakes will fail.
//!
//! Note that the [`PskReceiver`] supports lists for both of these items, so
//! zero-downtime migrations are possible. _Example_: if the client fleet wanted
//! to switch from Key A to Key B it would go through the following stages
//! 1. clients -> [A]     server -> [A]
//! 2. clients -> [A]     server -> [A & B]
//! 3. clients -> [A][B], server -> [A & B]
//! 4. clients ->    [B], server -> [A & B]
//! 5. clients ->    [B], server ->     [B]

mod codec;
mod epoch_schedule;
mod prefixed_list;
mod provider;
mod psk_derivation;
mod psk_parser;
mod receiver;
#[cfg(test)]
pub(crate) mod test_utils;

use std::time::Duration;

pub type KeyArn = String;
pub use provider::PskProvider;
pub use psk_derivation::PskVersion;
pub use receiver::PskReceiver;

// We have "pub" use statement so these can be fuzz tested
pub use codec::DecodeValue;
pub use psk_parser::PresharedKeyClientHello;

const ONE_HOUR: Duration = Duration::from_secs(3_600);

#[cfg(test)]
mod integration_tests {
    use aws_config::Region;
    use aws_sdk_kms::Client;
    use tracing_subscriber::EnvFilter;

    use crate::{
        provider::PskProvider,
        receiver::PskReceiver,
        test_utils::{configs_from_callbacks, handshake, KMS_KEY_ARN_A, KMS_KEY_ARN_B},
    };

    use super::*;

    #[tokio::test]
    async fn basic_handshake() {
        let psk_provider_a = PskProvider::initialize(
            test_utils::mocked_kms_client(),
            KMS_KEY_ARN_A.to_owned(),
            |_| {},
        )
        .await
        .unwrap();
        let psk_provider_b = PskProvider::initialize(
            test_utils::mocked_kms_client(),
            KMS_KEY_ARN_B.to_owned(),
            |_| {},
        )
        .await
        .unwrap();
        let psk_receiver = PskReceiver::initialize(
            test_utils::mocked_kms_client(),
            vec![KMS_KEY_ARN_A.to_owned(), KMS_KEY_ARN_B.to_owned()],
            |_| {},
        )
        .await
        .unwrap();

        let client_config_a = test_utils::make_client_config(psk_provider_a);
        let client_config_b = test_utils::make_client_config(psk_provider_b);
        let server_config = test_utils::make_server_config(psk_receiver);

        handshake(&client_config_a, &server_config).await.unwrap();
        handshake(&client_config_b, &server_config).await.unwrap();
    }

    /// if the server only trusts key a, then a handshake with a psk from key b
    /// will fail
    #[tokio::test]
    async fn untrusted_key_arn() {
        let psk_provider_a = PskProvider::initialize(
            test_utils::mocked_kms_client(),
            KMS_KEY_ARN_A.to_owned(),
            |_| {},
        )
        .await
        .unwrap();
        let psk_provider_b = PskProvider::initialize(
            test_utils::mocked_kms_client(),
            KMS_KEY_ARN_B.to_owned(),
            |_| {},
        )
        .await
        .unwrap();
        let psk_receiver = PskReceiver::initialize(
            test_utils::mocked_kms_client(),
            vec![KMS_KEY_ARN_A.to_owned()],
            |_| {},
        )
        .await
        .unwrap();

        let client_config_a = test_utils::make_client_config(psk_provider_a);
        let client_config_b = test_utils::make_client_config(psk_provider_b);
        let server_config = test_utils::make_server_config(psk_receiver);

        handshake(&client_config_a, &server_config).await.unwrap();
        let err = handshake(&client_config_b, &server_config)
            .await
            .unwrap_err()
            .to_string();
        // e.g. "no matching kms binder found for session c69d62609826836e718a7f1509effbde"
        assert!(err.contains("no matching kms binder found for session "));
    }
}
