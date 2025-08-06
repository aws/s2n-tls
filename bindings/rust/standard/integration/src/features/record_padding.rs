// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use openssl::ssl::SslContextBuilder;
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    openssl_extension::SslContextExtension,
    SigType, TlsConnPair,
};

const AES_GCM_TAG_LEN: u16 = 16;

/// s2n-tls must correctly handle padded records.
///
/// Record padding is new in TLS 1.3
///
/// We configure an openssl peer to use padded records using `SSL_CTX_set_block_padding`.
/// This function will pad records to a multiple of the supplied `pad_to` size.
/// https://docs.openssl.org/1.1.1/man3/SSL_CTX_set_record_padding_callback/
///
/// Out of an abundance of caution, we do a "shallow check" that openssl is correctly
/// padding the records by confirming that the encrypted record length is the
/// expected length.
#[test]
fn record_padding() {
    const SEND_SIZES: [usize; 6] = [1, 10, 100, 1_000, 5_000, 10_000];
    const PAD_TO_CASES: [usize; 4] = [512, 1_024, 4_096, 16_000];

    fn s2n_server_case(pad_to: usize) {
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs.client.set_block_padding(pad_to);
            configs.connection_pair()
        };
        pair.io.enable_recording();

        pair.handshake().unwrap();
        for send in SEND_SIZES {
            assert!(pair.round_trip_assert(send).is_ok());
        }
        pair.shutdown().unwrap();

        let correctly_padded = pair
            .io
            .client_record_sizes()
            .into_iter()
            // skip the first two records, because unencrypted records are not padded
            .skip(2)
            .all(|record_length| {
                let record_without_tag = record_length - AES_GCM_TAG_LEN;
                record_without_tag % (pad_to as u16) == 0
            });
        assert!(correctly_padded);
    }

    fn s2n_client_case(pad_to: usize) {
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<s2n_tls::config::Builder, SslContextBuilder>::default();
            configs.server.set_block_padding(pad_to);
            configs.connection_pair()
        };
        pair.io.enable_recording();

        pair.handshake().unwrap();
        for send in SEND_SIZES {
            assert!(pair.round_trip_assert(send).is_ok());
        }
        pair.shutdown().unwrap();

        let correctly_padded = pair
            .io
            .server_record_sizes()
            .into_iter()
            // skip the first two records, because unencrypted records are not padded
            .skip(2)
            .all(|record_length| {
                let record_without_tag = record_length - AES_GCM_TAG_LEN;
                record_without_tag % (pad_to as u16) == 0
            });
        assert!(correctly_padded);
    }

    PAD_TO_CASES.into_iter().for_each(|pad_to| {
        s2n_server_case(pad_to);
        s2n_client_case(pad_to);
    });
}
