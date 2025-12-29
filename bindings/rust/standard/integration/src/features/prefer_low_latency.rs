// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::capability_check::{required_capability, Capability};
use openssl::ssl::{SslContextBuilder, SslVersion};
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair,
};

/// Maximum observed TLS application-data record payload size when
/// `s2n_connection_prefer_low_latency()` is enabled under TLS 1.3.
///
/// This reflects TLS 1.3 record-protection overhead when using AES-GCM.
const TLS13_SMALL_RECORD_MAX: usize = 1_452;

/// Maximum observed TLS application-data record payload size when
/// `s2n_connection_prefer_low_latency()` is enabled under TLS 1.2.
///
/// TLS 1.2 includes additional per-record overhead compared to TLS 1.3.
const TLS12_SMALL_RECORD_MAX: usize = 1_472;

const APP_DATA_SIZE: usize = 100_000;

fn assert_all_small(record_sizes: &[u16], max: usize) {
    // Skip the final trailing partial record.
    let sizes = if record_sizes.len() > 1 {
        &record_sizes[..record_sizes.len() - 1]
    } else {
        record_sizes
    };

    assert!(!sizes.is_empty());

    for &size in sizes {
        assert!(size as usize <= max,);
    }
}

// === TLS 1.3 ===

#[test]
fn s2n_server_prefer_low_latency_tls13() {
    required_capability(&[Capability::Tls13], || {
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs.connection_pair()
        };

        pair.server.connection_mut().prefer_low_latency().unwrap();
        pair.handshake().unwrap();

        pair.io.enable_recording();
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();

        let sizes = pair.io.server_record_sizes();
        assert_all_small(&sizes, TLS13_SMALL_RECORD_MAX);
        assert!(pair.negotiated_tls13());

        pair.shutdown().unwrap();
    });
}

#[test]
fn s2n_client_prefer_low_latency_tls13() {
    required_capability(&[Capability::Tls13], || {
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = {
            let configs =
                TlsConfigBuilderPair::<s2n_tls::config::Builder, SslContextBuilder>::default();
            configs.connection_pair()
        };

        pair.client.connection_mut().prefer_low_latency().unwrap();
        pair.handshake().unwrap();

        pair.io.enable_recording();
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();

        let sizes = pair.io.client_record_sizes();
        assert_all_small(&sizes, TLS13_SMALL_RECORD_MAX);
        assert!(pair.negotiated_tls13());

        pair.shutdown().unwrap();
    });
}

// === TLS 1.2 ===

#[test]
fn s2n_server_prefer_low_latency_tls12() {
    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
        let mut configs =
            TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
        configs
            .client
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        configs.connection_pair()
    };

    pair.server.connection_mut().prefer_low_latency().unwrap();
    pair.handshake().unwrap();

    pair.io.enable_recording();
    pair.round_trip_assert(APP_DATA_SIZE).unwrap();

    let sizes = pair.io.server_record_sizes();
    assert_all_small(&sizes, TLS12_SMALL_RECORD_MAX);

    pair.shutdown().unwrap();
}

#[test]
fn s2n_client_prefer_low_latency_tls12() {
    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = {
        let mut configs =
            TlsConfigBuilderPair::<s2n_tls::config::Builder, SslContextBuilder>::default();
        configs
            .server
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();

        configs.connection_pair()
    };

    pair.client.connection_mut().prefer_low_latency().unwrap();
    pair.handshake().unwrap();

    pair.io.enable_recording();
    pair.round_trip_assert(APP_DATA_SIZE).unwrap();

    let sizes = pair.io.client_record_sizes();
    assert_all_small(&sizes, TLS12_SMALL_RECORD_MAX);

    pair.shutdown().unwrap();
}
