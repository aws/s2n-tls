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
    fn validate_dynamic_sizing(record_sizes: &[u16], phase_name: &str) {
        // Skip the final record to avoid false failures from a trailing partial record
        let sizes = if record_sizes.len() > 1 {
            &record_sizes[..record_sizes.len() - 1]
        } else {
            record_sizes
        };

        let mut total_sent = 0usize;
        let mut saw_small = false;
        let mut saw_large = false;

        if phase_name.contains("Phase 2") {
            for &size in sizes {
                assert!(
                    size as usize > SMALL_RECORD_MAX,
                    "{}: Expected all large records in steady state, got {} bytes",
                    phase_name, size
                );
            }
            return;
        }

        for &size in sizes {
            let before_threshold = total_sent < RESIZE_THRESHOLD;

            if before_threshold {
                assert!(
                    size as usize <= SMALL_RECORD_MAX,
                    "{}: Expected small record during ramp-up, got {} bytes (max {})",
                    phase_name, size, SMALL_RECORD_MAX
                );
                saw_small = true;
            } else {
                assert!(
                    size as usize > SMALL_RECORD_MAX,
                    "{}: Expected large record after threshold, got {} bytes",
                    phase_name, size
                );
                saw_large = true;
            }

            total_sent += size as usize;
        }

        assert!(saw_small, "{}: Expected some small records", phase_name);
        assert!(saw_large, "{}: Expected some large records after threshold", phase_name);
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
            .set_dynamic_record_threshold(RESIZE_THRESHOLD as u32, TIMEOUT_THRESHOLD as u16)
            .unwrap();

        pair.handshake().unwrap();
        // Dynamic record sizing only works with TLS 1.3
        assert!(pair.negotiated_tls13());

        // Start recording AFTER handshake completion to only capture application data
        pair.io.enable_recording();

        // Phase 1: Initial ramp up - should start with small records, then switch to large records
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase1_sizes = pair.io.server_record_sizes();
        validate_dynamic_sizing(&phase1_sizes, "Phase 1");

        pair.io.server_tx_transcript.borrow_mut().clear();

        // Phase 2: Steady state - there should not be any small records
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase2_sizes = pair.io.server_record_sizes();
        validate_dynamic_sizing(&phase2_sizes, "Phase 2");

        pair.io.server_tx_transcript.borrow_mut().clear();

        // Phase 3: Timeout threshold - connection should "ramp up" again after timeout
        sleep(Duration::from_secs(TIMEOUT_THRESHOLD + 1));
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase3_sizes = pair.io.server_record_sizes();
        validate_dynamic_sizing(&phase3_sizes, "Phase 3");

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
            .set_dynamic_record_threshold(RESIZE_THRESHOLD as u32, TIMEOUT_THRESHOLD as u16)
            .unwrap();

        pair.handshake().unwrap();
        // Dynamic record sizing only works with TLS 1.3
        assert!(pair.negotiated_tls13());

        // Start recording AFTER handshake completion to only capture application data
        pair.io.enable_recording();

        // Phase 1: Initial ramp up - should start with small records, then switch to large records
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase1_sizes = pair.io.client_record_sizes();
        validate_dynamic_sizing(&phase1_sizes, "Phase 1");

        pair.io.client_tx_transcript.borrow_mut().clear();

        // Phase 2: Steady state - there should not be any small records
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase2_sizes = pair.io.client_record_sizes();
        validate_dynamic_sizing(&phase2_sizes, "Phase 2");

        pair.io.client_tx_transcript.borrow_mut().clear();

        // Phase 3: Timeout threshold - connection should "ramp up" again after timeout
        sleep(Duration::from_secs(TIMEOUT_THRESHOLD + 1));
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();
        let phase3_sizes = pair.io.client_record_sizes();
        validate_dynamic_sizing(&phase3_sizes, "Phase 3");

        pair.shutdown().unwrap();
    }

    required_capability(&[Capability::Tls13], || {
        s2n_server_case();
        s2n_client_case();
    });
}
