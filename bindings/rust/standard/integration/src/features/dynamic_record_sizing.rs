// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use openssl::ssl::SslContextBuilder;
use std::{thread::sleep, time::Duration};
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair,
};

/// The byte threshold at which records switch from small to large
const RESIZE_THRESHOLD: usize = 16_000;
/// Maximum size for small records during ramp-up (single Ethernet frame limit)
const SMALL_RECORD_MAX: usize = 1_500;
/// Total application data size (chosen so the final record is always more than small size)
const APP_DATA_SIZE: usize = 100_000;
/// Duration of inactivity before resetting to small records
const TIMEOUT_THRESHOLD: Duration = Duration::from_secs(1);

/// Tests s2n-tls dynamic record sizing behavior.
///
/// This test explicitly validates the s2n_connection_set_dynamic_record_threshold() method
/// by configuring the threshold and validating the three phases of dynamic record sizing:
/// 1. Initial ramp-up: small records until threshold, then large records
/// 2. Steady state: all large records  
/// 3. Post-timeout ramp-up: small records again after timeout, then large records
#[test]
fn dynamic_record_sizing() {
    #[derive(Debug, Clone, Copy)]
    enum Phase {
        RampUp,
        SteadyState,
    }

    /// Validate record sizes based on the phase:
    /// - RampUp: expect small records until threshold, then large
    /// - SteadyState: expect all records to be large
    fn validate_dynamic_sizing(record_sizes: &[u16], phase: Phase) {
        println!("Checking record sizes for {phase:?}");

        // Skip the final record to avoid false failures from a trailing partial record
        let sizes = if record_sizes.len() > 1 {
            &record_sizes[..record_sizes.len() - 1]
        } else {
            record_sizes
        };

        match phase {
            Phase::SteadyState => {
                let all_large = sizes.iter().all(|&size| size as usize > SMALL_RECORD_MAX);
                assert!(all_large);
            }
            Phase::RampUp => {
                // Partition records into small (before threshold) and large (after threshold)
                let (small_records, large_records): (Vec<_>, Vec<_>) = sizes
                    .iter()
                    .scan(0usize, |total, &size| {
                        let before_threshold = *total < RESIZE_THRESHOLD;
                        *total += size as usize;
                        Some((size, before_threshold))
                    })
                    .partition(|(_, before_threshold)| *before_threshold);

                // Validate all small records are within limit
                for &(size, _) in &small_records {
                    assert!(size as usize <= SMALL_RECORD_MAX);
                }

                // Validate all large records exceed limit
                for &(size, _) in &large_records {
                    assert!(size as usize > SMALL_RECORD_MAX);
                }

                assert!(!small_records.is_empty());
                assert!(!large_records.is_empty());
            }
        }
    }

    fn s2n_server_case() {
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs.connection_pair()
        };

        // Set dynamic record threshold on s2n-tls server
        pair.server
            .connection_mut()
            .set_dynamic_record_threshold(
                RESIZE_THRESHOLD as u32,
                TIMEOUT_THRESHOLD.as_secs() as u16,
            )
            .unwrap();

        pair.handshake().unwrap();

        // Start recording AFTER handshake completion to only capture application data
        pair.io.enable_recording();

        // Phase 1: Initial ramp up - should start with small records, then switch to large records
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase1_sizes = pair.io.server_record_sizes();
        validate_dynamic_sizing(&phase1_sizes, Phase::RampUp);

        pair.io.server_tx_transcript.borrow_mut().clear();

        // Phase 2: Steady state - there should not be any small records
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase2_sizes = pair.io.server_record_sizes();
        validate_dynamic_sizing(&phase2_sizes, Phase::SteadyState);

        pair.io.server_tx_transcript.borrow_mut().clear();

        // Phase 3: Timeout threshold - connection should "ramp up" again after timeout
        sleep(TIMEOUT_THRESHOLD + Duration::from_secs(1));
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase3_sizes = pair.io.server_record_sizes();
        validate_dynamic_sizing(&phase3_sizes, Phase::RampUp);

        pair.shutdown().unwrap();
    }

    fn s2n_client_case() {
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = {
            let configs =
                TlsConfigBuilderPair::<s2n_tls::config::Builder, SslContextBuilder>::default();
            configs.connection_pair()
        };

        // Set dynamic record threshold on s2n-tls client
        pair.client
            .connection_mut()
            .set_dynamic_record_threshold(
                RESIZE_THRESHOLD as u32,
                TIMEOUT_THRESHOLD.as_secs() as u16,
            )
            .unwrap();

        pair.handshake().unwrap();

        // Start recording AFTER handshake completion to only capture application data
        pair.io.enable_recording();

        // Phase 1: Initial ramp up - should start with small records, then switch to large records
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase1_sizes = pair.io.client_record_sizes();
        validate_dynamic_sizing(&phase1_sizes, Phase::RampUp);

        pair.io.client_tx_transcript.borrow_mut().clear();

        // Phase 2: Steady state - there should not be any small records
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase2_sizes = pair.io.client_record_sizes();
        validate_dynamic_sizing(&phase2_sizes, Phase::SteadyState);

        pair.io.client_tx_transcript.borrow_mut().clear();

        // Phase 3: Timeout threshold - connection should "ramp up" again after timeout
        sleep(TIMEOUT_THRESHOLD + Duration::from_secs(1));
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase3_sizes = pair.io.client_record_sizes();
        validate_dynamic_sizing(&phase3_sizes, Phase::RampUp);

        pair.shutdown().unwrap();
    }

    s2n_server_case();
    s2n_client_case();
}
