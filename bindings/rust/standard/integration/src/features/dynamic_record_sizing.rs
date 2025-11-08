// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use openssl::ssl::SslContextBuilder;
use std::{thread::sleep, time::Duration};
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair,
};

use crate::capability_check::{required_capability, Capability};

// Constants for dynamic record threshold testing:
// - RESIZE_THRESHOLD: The byte threshold at which records switch from small to large
// - SMALL_RECORD_MAX: Maximum size for small records during ramp-up (single Ethernet frame limit)
// - APP_DATA_SIZE: Total application data size (chosen so the final record is always more than small size)
// - TIMEOUT_THRESHOLD: Seconds of inactivity before resetting to small records
const RESIZE_THRESHOLD: usize = 16_000;
const SMALL_RECORD_MAX: usize = 1_500;
const APP_DATA_SIZE: usize = 100_000;
const TIMEOUT_THRESHOLD: u64 = 1;

/// Tests s2n-tls dynamic record sizing behavior.
///
/// This test explicitly validates the s2n_connection_set_dynamic_record_threshold() method
/// by configuring the threshold and validating the three phases of dynamic record sizing:
/// 1. Initial ramp-up: small records until threshold, then large records
/// 2. Steady state: all large records  
/// 3. Post-timeout ramp-up: small records again after timeout, then large records
///
/// Note that the resize threshold is only counting application data, not handshake messages.
/// The amount of data is chosen so that we don't have to worry about "remainder" data.
#[test]
fn dynamic_record_sizing() {
    /// Validate record sizes based on the phase:
    /// - Phase 1 & 3: expect small records until threshold, then large
    /// - Phase 2: expect all records to be large (steady state)
    fn validate_dynamic_sizing(records: &[Vec<u8>], phase_name: &str) -> (usize, usize) {
        let mut total_sent = 0usize;
        let mut small_count = 0usize;
        let mut large_count = 0usize;

        for record in records {
            let before_threshold = total_sent < RESIZE_THRESHOLD;

            if before_threshold {
                assert!(
                    record.len() <= SMALL_RECORD_MAX,
                    "{}: Record should be small during ramp-up, got {} bytes (max: {})",
                    phase_name,
                    record.len(),
                    SMALL_RECORD_MAX
                );
                small_count += 1;
            } else {
                assert!(
                    record.len() > SMALL_RECORD_MAX,
                    "{}: Record should be large after threshold, got {} bytes",
                    phase_name,
                    record.len()
                );
                large_count += 1;
            }

            total_sent += record.len();
        }

        // Steady-state phase: all records should be large
        if phase_name.contains("Phase 2") {
            for record in records {
                assert!(
                    record.len() > SMALL_RECORD_MAX,
                    "{}: All records should be large in steady state, got {} bytes",
                    phase_name,
                    record.len()
                );
                large_count += 1;
            }
            return (small_count, large_count);
        }

        assert!(small_count > 0, "{}: Expected some small records", phase_name);
        assert!(large_count > 0, "{}: Expected some large records after threshold", phase_name);

        (small_count, large_count)
    }

    fn s2n_server_case() {
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs.connection_pair()
        };

        // Set dynamic record threshold on s2n-tls server
        pair.server
            .connection
            .set_dynamic_record_threshold(RESIZE_THRESHOLD as u32, TIMEOUT_THRESHOLD as u16)
            .unwrap();

        pair.handshake().unwrap();
        assert!(pair.negotiated_tls13());

        // Start recording AFTER handshake completion to only capture application data
        pair.io.enable_recording();

        // Phase 1: Initial ramp up - should start with small records, then switch to large records
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase1_records = pair.io.server_record_writes();
        validate_dynamic_sizing(&phase1_records, "Phase 1");

        pair.io.server_tx_transcript.borrow_mut().clear();

        // Phase 2: Steady state - there should not be any small records
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase2_records = pair.io.server_record_writes();
        validate_dynamic_sizing(&phase2_records, "Phase 2");

        pair.io.server_tx_transcript.borrow_mut().clear();

        // Phase 3: Timeout threshold - connection should "ramp up" again after timeout
        sleep(Duration::from_secs(TIMEOUT_THRESHOLD + 1));
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase3_records = pair.io.server_record_writes();
        validate_dynamic_sizing(&phase3_records, "Phase 3");

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
            .connection
            .set_dynamic_record_threshold(RESIZE_THRESHOLD as u32, TIMEOUT_THRESHOLD as u16)
            .unwrap();

        pair.handshake().unwrap();
        assert!(pair.negotiated_tls13());

        // Start recording AFTER handshake completion to only capture application data
        pair.io.enable_recording();

        // Phase 1: Initial ramp up - should start with small records, then switch to large records
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase1_records = pair.io.client_record_writes();
        validate_dynamic_sizing(&phase1_records, "Phase 1");

        pair.io.client_tx_transcript.borrow_mut().clear();

        // Phase 2: Steady state - there should not be any small records
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase2_records = pair.io.client_record_writes();
        validate_dynamic_sizing(&phase2_records, "Phase 2");

        pair.io.client_tx_transcript.borrow_mut().clear();

        // Phase 3: Timeout threshold - connection should "ramp up" again after timeout
        sleep(Duration::from_secs(TIMEOUT_THRESHOLD + 1));
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase3_records = pair.io.client_record_writes();
        validate_dynamic_sizing(&phase3_records, "Phase 3");

        pair.shutdown().unwrap();
    }

    required_capability(&[Capability::Tls13], || {
        s2n_server_case();
        s2n_client_case();
    });
}
