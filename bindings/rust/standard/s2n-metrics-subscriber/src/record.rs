// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// allow dead code until we have the EMF conversion code in place, otherwise the
// record fields will have a "never read" warning
#![allow(dead_code)]

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

use crate::static_lists::{
    self, TlsParam, ToStaticString, CIPHERS_AVAILABLE_IN_S2N, GROUPS_AVAILABLE_IN_S2N,
    SIGNATURE_SCHEMES_AVAILABLE_IN_S2N, VERSIONS_AVAILABLE_IN_S2N,
};

const GROUP_COUNT: usize = GROUPS_AVAILABLE_IN_S2N.len();
const CIPHER_COUNT: usize = CIPHERS_AVAILABLE_IN_S2N.len();
const SIGNATURE_COUNT: usize = SIGNATURE_SCHEMES_AVAILABLE_IN_S2N.len();
const PROTOCOL_COUNT: usize = VERSIONS_AVAILABLE_IN_S2N.len();

/// Metric Record is an opaque type which implements [`metrique_writer::Entry`].
///
/// This is the preferred type for public s2n-tls-metric-subscriber traits and
/// interfaces.
// This currently just holds a single struct. In the future we will
// likely rely on an enum to handle different record types, e.g. SessionResumptionFailure.
#[derive(Debug, Clone)]
pub struct MetricRecord {
    handshake: HandshakeRecord,
}

impl MetricRecord {
    pub(crate) fn new(handshake: HandshakeRecord) -> Self {
        Self { handshake }
    }
}
/// The S2NMetricRecord stores various metrics
#[derive(Debug)]
pub(crate) struct HandshakeRecordInProgress {
    /// This is used to send a frozen version back to the Aggregator, after which
    /// point it can be exported. This is only used in the drop impl.
    exporter: std::sync::mpsc::Sender<HandshakeRecord>,

    sample_count: AtomicU64,

    negotiated_protocols: [AtomicU64; PROTOCOL_COUNT],
    negotiated_ciphers: [AtomicU64; CIPHER_COUNT],
    negotiated_groups: [AtomicU64; GROUP_COUNT],
    negotiated_signatures: [AtomicU64; SIGNATURE_COUNT],

    /// sum of handshake duration, including network latency and waiting
    handshake_duration_us: AtomicU64,
    /// sum of handshake compute
    handshake_compute_us: AtomicU64,
}

fn relaxed_freeze<const T: usize>(array: &[AtomicU64; T]) -> [u64; T] {
    array
        .each_ref()
        .map(|counter| counter.load(Ordering::Relaxed))
}

impl HandshakeRecordInProgress {
    pub fn new(exporter: std::sync::mpsc::Sender<HandshakeRecord>) -> Self {
        // default is not implemented for arrays this large
        let ciphers = [0; CIPHER_COUNT].map(|_| AtomicU64::default());
        Self {
            sample_count: Default::default(),

            negotiated_groups: Default::default(),
            negotiated_ciphers: ciphers,
            negotiated_protocols: Default::default(),
            negotiated_signatures: Default::default(),

            handshake_duration_us: Default::default(),
            handshake_compute_us: Default::default(),
            exporter,
        }
    }

    pub fn update(
        &self,
        conn: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) {
        self.sample_count.fetch_add(1, Ordering::Relaxed);

        ////////////////////////////////////////////////////////////////////////
        /////////////////////   fields from connection   ///////////////////////
        ////////////////////////////////////////////////////////////////////////

        conn.selected_signature_scheme()
            .and_then(|name| TlsParam::SignatureScheme.description_to_index(name))
            .and_then(|index| self.negotiated_signatures.get(index))
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));

        ////////////////////////////////////////////////////////////////////////
        //////////////////////   fields from event   ///////////////////////////
        ////////////////////////////////////////////////////////////////////////

        TlsParam::Version
            .description_to_index(event.protocol_version().to_static_string())
            .and_then(|index| self.negotiated_protocols.get(index))
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));

        static_lists::cipher_ossl_name_to_index(event.cipher())
            .and_then(|index| self.negotiated_ciphers.get(index))
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));

        event
            .group()
            .and_then(|name| TlsParam::Group.description_to_index(name))
            .and_then(|index| self.negotiated_groups.get(index))
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));

        // Assumption: durations are less than 500,000 years, otherwise this cast
        // will panic
        self.handshake_compute_us.fetch_add(
            event.synchronous_time().as_micros() as u64,
            Ordering::Relaxed,
        );
        self.handshake_duration_us
            .fetch_add(event.duration().as_micros() as u64, Ordering::Relaxed);
    }

    /// make a copy of this record to be exported.
    ///
    /// ### A Note On Ordering Correctness
    ///
    /// It is important that this function observes the results of all the `fetch_add`
    /// operations on other threads.
    ///
    /// Simple Intuition: This function takes a `&mut`. Therefore the rust compiler
    /// enforces that there are no other references to this memory and there isn't
    /// anything to actually synchronize. So a Relaxed load is fine.
    fn finish(&mut self) -> HandshakeRecord {
        HandshakeRecord {
            freeze_time: SystemTime::now(),
            sample_count: self.sample_count.load(Ordering::Relaxed),
            negotiated_protocols: relaxed_freeze(&self.negotiated_protocols),
            negotiated_ciphers: relaxed_freeze(&self.negotiated_ciphers),
            negotiated_groups: relaxed_freeze(&self.negotiated_groups),
            negotiated_signatures: relaxed_freeze(&self.negotiated_signatures),
            handshake_duration_us: self.handshake_duration_us.load(Ordering::Relaxed),
            handshake_compute_us: self.handshake_compute_us.load(Ordering::Relaxed),
        }
    }
}

impl Drop for HandshakeRecordInProgress {
    fn drop(&mut self) {
        let frozen = self.finish();
        // no available way to report error
        let _ = self.exporter.send(frozen);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HandshakeRecord {
    freeze_time: SystemTime,

    sample_count: u64,

    negotiated_protocols: [u64; PROTOCOL_COUNT],
    negotiated_ciphers: [u64; CIPHER_COUNT],
    negotiated_groups: [u64; GROUP_COUNT],
    negotiated_signatures: [u64; SIGNATURE_COUNT],

    handshake_duration_us: u64,
    handshake_compute_us: u64,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestEndpoint;

    #[test]
    fn record_contents() {
        let endpoint = TestEndpoint::new();

        let result = endpoint.client_handshake();
        endpoint.subscriber.finish_record();
        let record = endpoint.rx.recv().unwrap();
        let record = record.handshake;

        assert_eq!(record.sample_count, 1);
        assert_eq!(record.negotiated_ciphers.iter().sum::<u64>(), 1);
        assert_eq!(record.negotiated_groups.iter().sum::<u64>(), 1);
        assert_eq!(record.negotiated_signatures.iter().sum::<u64>(), 1);
        assert_eq!(record.negotiated_protocols.iter().sum::<u64>(), 1);

        let expected_version = result
            .client
            .actual_protocol_version()
            .unwrap()
            .to_static_string();
        let expected_index = TlsParam::Version
            .description_to_index(expected_version)
            .unwrap();
        assert_eq!(record.negotiated_protocols[expected_index], 1);

        let expected_cipher = result.client.cipher_suite().unwrap().to_owned();
        let expected_index =
            static_lists::cipher_ossl_name_to_index(expected_cipher.as_str()).unwrap();
        assert_eq!(record.negotiated_ciphers[expected_index], 1);

        let expected_group = result
            .client
            .selected_key_exchange_group()
            .unwrap()
            .to_owned();
        let expected_index = TlsParam::Group
            .description_to_index(expected_group.as_str())
            .unwrap();
        assert_eq!(record.negotiated_groups[expected_index], 1);

        let expected_sig = result
            .client
            .selected_signature_scheme()
            .unwrap()
            .to_owned();
        let expected_index = TlsParam::SignatureScheme
            .description_to_index(expected_sig.as_str())
            .unwrap();
        assert_eq!(record.negotiated_signatures[expected_index], 1);
    }

    #[test]
    fn multiple_records() {
        let endpoint = TestEndpoint::new();

        endpoint.client_handshake();
        endpoint.client_handshake();
        endpoint.client_handshake();

        endpoint.subscriber.finish_record();
        let record = endpoint.rx.recv().unwrap();
        let record = record.handshake;

        assert_eq!(record.sample_count, 3);
        assert_eq!(record.negotiated_ciphers.iter().sum::<u64>(), 3);
        assert_eq!(record.negotiated_groups.iter().sum::<u64>(), 3);
        assert_eq!(record.negotiated_signatures.iter().sum::<u64>(), 3);
        assert_eq!(record.negotiated_protocols.iter().sum::<u64>(), 3);
    }

    /// Make sure that the compute time is less than the overall handshake time.
    ///
    /// Additionally, make sure that three handshakes takes longer than one handshake.
    /// This provides some confidence that we are correctly e.g. adding amounts
    #[test]
    fn timers() {
        let endpoint = TestEndpoint::new();

        endpoint.client_handshake();
        endpoint.subscriber.finish_record();
        let single_handshake = endpoint.rx.recv().unwrap().handshake;

        endpoint.client_handshake();
        endpoint.client_handshake();
        endpoint.client_handshake();
        endpoint.subscriber.finish_record();
        let multiple_handshakes = endpoint.rx.recv().unwrap().handshake;

        assert!(single_handshake.handshake_compute_us <= single_handshake.handshake_duration_us);
        assert!(
            multiple_handshakes.handshake_compute_us <= multiple_handshakes.handshake_duration_us
        );

        assert!(single_handshake.handshake_compute_us < multiple_handshakes.handshake_compute_us);
        assert!(single_handshake.handshake_duration_us < multiple_handshakes.handshake_duration_us);
    }
}
