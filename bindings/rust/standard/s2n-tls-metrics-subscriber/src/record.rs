// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use crate::{
    attribution::Attribution,
    compatibility::{Cnsa1, Cnsa2, Fips20251201, General20251201, TlsProfile},
    counter::{Counter, FrozenCounter},
    label::{State, metric_label},
    parsing::ClientHelloSupportedParameters,
    static_lists::{
        CIPHER_COUNT, Cipher, FiniteCounter, GROUP_COUNT, Group, PROTOCOL_COUNT, SIGNATURE_COUNT,
        Signature, TlsParam, ToStaticString, Version,
    },
};

/// Metric Record is an opaque type which implements [`metrique_writer::Entry`].
///
/// This is the preferred type for public s2n-tls-metric-subscriber traits and
/// interfaces.
// This currently just holds a single struct. In the future we will
// likely rely on an enum to handle different record types, e.g. SessionResumptionFailure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricRecord {
    pub(crate) attribution: Attribution,
    pub(crate) handshake: FrozenHandshakeRecord,
}

impl MetricRecord {
    pub(crate) fn new(handshake: FrozenHandshakeRecord, attribution: Attribution) -> Self {
        Self {
            attribution,
            handshake,
        }
    }
}

impl metrique_writer::Entry for MetricRecord {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        writer.value("service", &self.attribution.service);
        writer.value("resource", &self.attribution.resource);
        self.handshake.write(writer)
    }
}

/// The HandshakeRecordInProgress stores the in-flight counters for handshake
/// information - e.g. negotiated parameters.
#[derive(Debug)]
pub(crate) struct HandshakeRecordInProgress {
    /// This is used to send a frozen version back to the Aggregator, after which
    /// point it can be exported. This is only used in the drop impl.
    exporter: std::sync::mpsc::Sender<FrozenHandshakeRecord>,

    /// the total number of handshakes that this record represents.
    handshake_count: AtomicU64,

    negotiated_protocols: Counter<PROTOCOL_COUNT, Version>,
    negotiated_ciphers: Counter<CIPHER_COUNT, Cipher>,
    negotiated_groups: Counter<GROUP_COUNT, Group>,
    negotiated_signatures: Counter<SIGNATURE_COUNT, Signature>,

    // we do not attempt to detect supported parameters for SSLv2 formatted client
    // hellos
    sslv2_client_hello: AtomicU64,
    supported_protocols: Counter<PROTOCOL_COUNT, Version>,
    supported_ciphers: Counter<CIPHER_COUNT, Cipher>,
    supported_groups: Counter<GROUP_COUNT, Group>,
    supported_signatures: Counter<SIGNATURE_COUNT, Signature>,

    compatibility_general20251201: AtomicU64,
    compatibility_fips20251201: AtomicU64,
    compatibility_cnsa1: AtomicU64,
    compatibility_cnsa2: AtomicU64,

    /// sum of handshake duration, including network latency and waiting
    ///
    /// To get the average, divide this by handshake_count.
    handshake_duration_us: AtomicU64,
    /// sum of handshake compute
    ///
    /// To get the average, divide this by handshake_count.
    handshake_compute_us: AtomicU64,
}

impl HandshakeRecordInProgress {
    pub fn new(exporter: std::sync::mpsc::Sender<FrozenHandshakeRecord>) -> Self {
        Self {
            handshake_count: Default::default(),

            negotiated_groups: Counter::new(),
            negotiated_ciphers: Counter::new(),
            negotiated_protocols: Counter::new(),
            negotiated_signatures: Counter::new(),

            sslv2_client_hello: Default::default(),
            supported_groups: Counter::new(),
            supported_ciphers: Counter::new(),
            supported_protocols: Counter::new(),
            supported_signatures: Counter::new(),

            compatibility_general20251201: AtomicU64::default(),
            compatibility_fips20251201: AtomicU64::default(),
            compatibility_cnsa1: AtomicU64::default(),
            compatibility_cnsa2: AtomicU64::default(),

            handshake_duration_us: Default::default(),
            handshake_compute_us: Default::default(),
            exporter,
        }
    }

    pub fn update(
        &self,
        conn: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.handshake_count.fetch_add(1, Ordering::Relaxed);

        ////////////////////////////////////////////////////////////////////////
        /////////////////////   fields from connection   ///////////////////////
        ////////////////////////////////////////////////////////////////////////

        self.negotiated_signatures
            .increment_if_some(conn.signature_scheme().and_then(|s| s.parse().ok()));

        if conn.client_hello_is_sslv2()? {
            self.sslv2_client_hello.fetch_add(1, Ordering::Relaxed);
        } else {
            let supported_parameter = ClientHelloSupportedParameters::new(conn.client_hello()?);

            supported_parameter
                .supported_versions()?
                .iter()
                .for_each(|version| self.supported_protocols.increment(version));

            supported_parameter
                .supported_ciphers()?
                .iter()
                .for_each(|cipher| self.supported_ciphers.increment(cipher));

            supported_parameter
                .supported_groups()?
                .iter()
                .flatten()
                .for_each(|group| self.supported_groups.increment(group));

            supported_parameter
                .supported_signatures()?
                .iter()
                .flatten()
                .for_each(|signature| self.supported_signatures.increment(signature));

            if General20251201::supported(&supported_parameter) {
                self.compatibility_general20251201
                    .fetch_add(1, Ordering::Relaxed);
            }
            if Fips20251201::supported(&supported_parameter) {
                self.compatibility_fips20251201
                    .fetch_add(1, Ordering::Relaxed);
            }
            if Cnsa1::supported(&supported_parameter) {
                self.compatibility_cnsa1.fetch_add(1, Ordering::Relaxed);
            }
            if Cnsa2::supported(&supported_parameter) {
                self.compatibility_cnsa2.fetch_add(1, Ordering::Relaxed);
            }
        }

        ////////////////////////////////////////////////////////////////////////
        //////////////////////   fields from event   ///////////////////////////
        ////////////////////////////////////////////////////////////////////////

        self.negotiated_protocols
            .increment_if_some(event.protocol_version().to_static_string().parse().ok());

        self.negotiated_ciphers
            .increment_if_some(Cipher::from_openssl_name(event.cipher()));

        self.negotiated_groups
            .increment_if_some(event.group().and_then(|g| g.parse().ok()));

        // accuracy: as long as the handshake took less than 500,000 years
        // this cast will not truncate. We prefer truncation/less accurate metrics
        // over a panic.
        self.handshake_compute_us.fetch_add(
            event.synchronous_time().as_micros() as u64,
            Ordering::Relaxed,
        );
        self.handshake_duration_us
            .fetch_add(event.duration().as_micros() as u64, Ordering::Relaxed);

        Ok(())
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
    fn finish(&mut self) -> FrozenHandshakeRecord {
        FrozenHandshakeRecord {
            freeze_time: SystemTime::now(),
            handshake_count: self.handshake_count.load(Ordering::Relaxed),
            negotiated_protocols: self.negotiated_protocols.freeze(),
            negotiated_ciphers: self.negotiated_ciphers.freeze(),
            negotiated_groups: self.negotiated_groups.freeze(),
            negotiated_signatures: self.negotiated_signatures.freeze(),

            sslv2_client_hello: self.sslv2_client_hello.load(Ordering::Relaxed),
            supported_protocols: self.supported_protocols.freeze(),
            supported_ciphers: self.supported_ciphers.freeze(),
            supported_groups: self.supported_groups.freeze(),
            supported_signatures: self.supported_signatures.freeze(),

            compatibility_general20251201: self
                .compatibility_general20251201
                .load(Ordering::Relaxed),
            compatibility_fips20251201: self.compatibility_fips20251201.load(Ordering::Relaxed),
            compatibility_cnsa1: self.compatibility_cnsa1.load(Ordering::Relaxed),
            compatibility_cnsa2: self.compatibility_cnsa2.load(Ordering::Relaxed),

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

/// `SystemTime` has no meaningful `Default` impl for serde's purposes, so we
/// pick `UNIX_EPOCH` explicitly as the `#[serde(default = ...)]` target for
/// `freeze_time`.
fn system_time_epoch() -> SystemTime {
    SystemTime::UNIX_EPOCH
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct FrozenHandshakeRecord {
    #[serde(default = "system_time_epoch")]
    freeze_time: SystemTime,

    #[serde(default)]
    pub(crate) handshake_count: u64,

    #[serde(default)]
    negotiated_protocols: FrozenCounter<PROTOCOL_COUNT, Version>,
    #[serde(default)]
    negotiated_ciphers: FrozenCounter<CIPHER_COUNT, Cipher>,
    #[serde(default)]
    negotiated_groups: FrozenCounter<GROUP_COUNT, Group>,
    #[serde(default)]
    negotiated_signatures: FrozenCounter<SIGNATURE_COUNT, Signature>,

    #[serde(default)]
    sslv2_client_hello: u64,
    #[serde(default)]
    supported_protocols: FrozenCounter<PROTOCOL_COUNT, Version>,
    #[serde(default)]
    supported_ciphers: FrozenCounter<CIPHER_COUNT, Cipher>,
    #[serde(default)]
    supported_groups: FrozenCounter<GROUP_COUNT, Group>,
    #[serde(default)]
    supported_signatures: FrozenCounter<SIGNATURE_COUNT, Signature>,

    #[serde(default)]
    compatibility_general20251201: u64,
    #[serde(default)]
    compatibility_fips20251201: u64,
    #[serde(default)]
    compatibility_cnsa1: u64,
    #[serde(default)]
    compatibility_cnsa2: u64,

    #[serde(default)]
    handshake_duration_us: u64,
    #[serde(default)]
    handshake_compute_us: u64,
}

// This is just cfg(test) because we only use it in tests to assert on cases of
// all-zero records
#[cfg(test)]
impl Default for FrozenHandshakeRecord {
    fn default() -> Self {
        Self {
            freeze_time: SystemTime::UNIX_EPOCH,
            handshake_count: 0,
            negotiated_protocols: FrozenCounter::default(),
            negotiated_ciphers: FrozenCounter::default(),
            negotiated_groups: FrozenCounter::default(),
            negotiated_signatures: FrozenCounter::default(),
            sslv2_client_hello: 0,
            supported_protocols: FrozenCounter::default(),
            supported_ciphers: FrozenCounter::default(),
            supported_groups: FrozenCounter::default(),
            supported_signatures: FrozenCounter::default(),
            compatibility_general20251201: 0,
            compatibility_fips20251201: 0,
            compatibility_cnsa1: 0,
            compatibility_cnsa2: 0,
            handshake_duration_us: 0,
            handshake_compute_us: 0,
        }
    }
}

impl metrique_writer::Entry for FrozenHandshakeRecord {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        writer.timestamp(self.freeze_time);

        // Emit one label per non-zero slot for each (kind, state) cell.
        // The label uses the element's `Display` impl.
        fn write_counter<'a, const N: usize, T, W>(
            counter: &'a FrozenCounter<N, T>,
            parameter: TlsParam,
            state: State,
            writer: &mut W,
        ) where
            T: FiniteCounter<N>,
            W: metrique_writer::EntryWriter<'a>,
        {
            for (element, count) in counter.iter_non_zero() {
                let label = metric_label(element, parameter, state);
                writer.value(label, &count);
            }
        }

        write_counter(
            &self.negotiated_protocols,
            TlsParam::Version,
            State::Negotiated,
            writer,
        );
        write_counter(
            &self.negotiated_ciphers,
            TlsParam::Cipher,
            State::Negotiated,
            writer,
        );
        write_counter(
            &self.negotiated_groups,
            TlsParam::Group,
            State::Negotiated,
            writer,
        );
        write_counter(
            &self.negotiated_signatures,
            TlsParam::SignatureScheme,
            State::Negotiated,
            writer,
        );
        write_counter(
            &self.supported_protocols,
            TlsParam::Version,
            State::Supported,
            writer,
        );
        write_counter(
            &self.supported_ciphers,
            TlsParam::Cipher,
            State::Supported,
            writer,
        );
        write_counter(
            &self.supported_groups,
            TlsParam::Group,
            State::Supported,
            writer,
        );
        write_counter(
            &self.supported_signatures,
            TlsParam::SignatureScheme,
            State::Supported,
            writer,
        );

        writer.value(
            "compatibility.general20251201",
            &self.compatibility_general20251201,
        );
        writer.value(
            "compatibility.fips20251201",
            &self.compatibility_fips20251201,
        );
        writer.value("compatibility.cnsa1", &self.compatibility_cnsa1);
        writer.value("compatibility.cnsa2", &self.compatibility_cnsa2);

        writer.value("sslv2_client_hello", &self.sslv2_client_hello);
        writer.value("handshake_count", &self.handshake_count);
        writer.value("handshake_duration_us", &self.handshake_duration_us);
        writer.value("handshake_compute_us", &self.handshake_compute_us);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{ARBITRARY_POLICY_1, TestEndpoint};

    #[test]
    fn record_contents_negotiated_parameters() {
        let endpoint = TestEndpoint::new();

        let result = endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let record = &records[0].handshake;

        assert_eq!(record.handshake_count, 1);
        assert_eq!(record.negotiated_ciphers.total(), 1);
        assert_eq!(record.negotiated_groups.total(), 1);
        assert_eq!(record.negotiated_signatures.total(), 1);
        assert_eq!(record.negotiated_protocols.total(), 1);

        let expected_version = result
            .client
            .actual_protocol_version()
            .unwrap()
            .to_static_string();
        assert_eq!(record.negotiated_protocols.count_for(expected_version), 1);

        let expected_cipher = result.client.cipher_suite().unwrap().to_owned();
        let expected_cipher_description = Cipher::from_openssl_name(expected_cipher.as_str())
            .and_then(|cipher| cipher.known_description())
            .unwrap();
        assert_eq!(
            record
                .negotiated_ciphers
                .count_for(expected_cipher_description),
            1
        );

        let expected_group = result
            .client
            .selected_key_exchange_group()
            .unwrap()
            .to_owned();
        assert_eq!(
            record.negotiated_groups.count_for(expected_group.as_str()),
            1
        );

        let expected_sig = result.client.signature_scheme().unwrap().to_owned();
        assert_eq!(
            record
                .negotiated_signatures
                .count_for(expected_sig.as_str()),
            1
        );
    }

    #[test]
    fn record_contents_supported_parameters() {
        const EXPECTED_VERSIONS: &[&str] = &["TLSv1_3", "TLSv1_2"];
        const EXPECTED_CIPHERS: &[&str] = &[
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ];
        const EXPECTED_GROUPS: &[&str] = &["secp256r1", "secp384r1", "secp521r1", "x25519"];
        const EXPECTED_SIGS: &[&str] = &[
            "ecdsa_sha256",
            "ecdsa_sha384",
            "ecdsa_sha512",
            "rsa_pkcs1_sha256",
            "rsa_pkcs1_sha384",
            "rsa_pkcs1_sha512",
            "rsa_pss_rsae_sha256",
            "rsa_pss_rsae_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pss_pss_sha256",
            "rsa_pss_pss_sha384",
            "rsa_pss_pss_sha512",
        ];

        let endpoint = TestEndpoint::new();

        let _ = endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let record = &records[0].handshake;

        /// For every slot in `counter`, assert the count is 1 iff the slot's
        /// element description appears in `expected`, else 0.
        fn assert_supported_matches<const N: usize, T: FiniteCounter<N>>(
            counter: &FrozenCounter<N, T>,
            expected: &[&str],
        ) {
            let expected_slots: Vec<usize> = expected
                .iter()
                .map(|description| {
                    description
                        .parse::<T>()
                        .unwrap_or_else(|()| panic!("unknown description {description}"))
                        .slot_from_key()
                        .unwrap()
                })
                .collect();

            for (slot, &count) in counter.slots_for_test().iter().enumerate() {
                let name = T::key_from_slot(slot).unwrap();
                if expected_slots.contains(&slot) {
                    assert_eq!(count, 1, "{name} count is {count}, not one");
                } else {
                    assert_eq!(count, 0, "{name} count is {count}, not zero");
                }
            }
        }

        assert_supported_matches(&record.supported_protocols, EXPECTED_VERSIONS);
        assert_supported_matches(&record.supported_ciphers, EXPECTED_CIPHERS);
        assert_supported_matches(&record.supported_groups, EXPECTED_GROUPS);
        assert_supported_matches(&record.supported_signatures, EXPECTED_SIGS);
    }

    #[test]
    fn multiple_records() {
        let endpoint = TestEndpoint::new();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let record = &records[0].handshake;

        assert_eq!(record.handshake_count, 3);
        assert_eq!(record.negotiated_ciphers.total(), 3);
        assert_eq!(record.negotiated_groups.total(), 3);
        assert_eq!(record.negotiated_signatures.total(), 3);
        assert_eq!(record.negotiated_protocols.total(), 3);
    }

    /// A record with no handshakes should be entirely empty/default.
    #[test]
    fn empty_record() {
        let endpoint = TestEndpoint::new();

        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let mut record = records[0].handshake.clone();

        // ignore the freeze time, since that "default" value is set to the Unix Epoch.
        record.freeze_time = SystemTime::UNIX_EPOCH;
        assert_eq!(record, FrozenHandshakeRecord::default());
    }

    /// ARBITRARY_POLICY_1 (20240503 / default_tls13) should be compatible with
    /// General, Fips, and Cnsa1 profiles, but not CNSA2 (which requires MLKEM1024
    /// and mldsa87).
    #[test]
    fn record_contents_compatibility_metrics() {
        let endpoint = TestEndpoint::new();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let record = &records[0].handshake;

        assert_eq!(record.compatibility_general20251201, 1);
        assert_eq!(record.compatibility_fips20251201, 1);
        assert_eq!(record.compatibility_cnsa1, 1);
        assert_eq!(record.compatibility_cnsa2, 0);
    }

    /// Make sure that the compute time is less than the overall handshake time.
    ///
    /// Additionally, make sure that three handshakes takes longer than one handshake.
    /// This provides some confidence that we are correctly e.g. adding amounts
    #[test]
    fn timers() {
        let endpoint = TestEndpoint::new();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let single_handshake = &records[0].handshake;

        assert!(single_handshake.handshake_compute_us <= single_handshake.handshake_duration_us);
        drop(records);

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let single_handshake = &records[0].handshake;
        let multiple_handshakes = &records[1].handshake;

        assert!(
            multiple_handshakes.handshake_compute_us <= multiple_handshakes.handshake_duration_us
        );

        assert!(single_handshake.handshake_compute_us < multiple_handshakes.handshake_compute_us);
        assert!(single_handshake.handshake_duration_us < multiple_handshakes.handshake_duration_us);
    }

    /// A JSON payload that only includes `handshake_count` deserializes
    /// successfully: `#[serde(default)]` on every other field fills it with
    /// its documented default (0 for integer counters, `SystemTime::UNIX_EPOCH`
    /// for `freeze_time`, a zero-filled `FrozenCounter` for per-kind fields).
    #[test]
    fn deserialize_missing_fields_uses_defaults() {
        let json = r#"{"handshake_count": 10}"#;
        let record: FrozenHandshakeRecord = serde_json::from_str(json).unwrap();

        assert_eq!(record.handshake_count, 10);
        assert_eq!(record.freeze_time, SystemTime::UNIX_EPOCH);

        // Per-kind counters default to a zero-filled slab of the right length.
        assert_eq!(record.negotiated_protocols, FrozenCounter::default());
        assert_eq!(record.negotiated_ciphers, FrozenCounter::default());
        assert_eq!(record.negotiated_groups, FrozenCounter::default());
        assert_eq!(record.negotiated_signatures, FrozenCounter::default());
        assert_eq!(record.supported_protocols, FrozenCounter::default());
        assert_eq!(record.supported_ciphers, FrozenCounter::default());
        assert_eq!(record.supported_groups, FrozenCounter::default());
        assert_eq!(record.supported_signatures, FrozenCounter::default());

        // Scalar integer fields default to zero.
        assert_eq!(record.sslv2_client_hello, 0);
        assert_eq!(record.compatibility_general20251201, 0);
        assert_eq!(record.compatibility_fips20251201, 0);
        assert_eq!(record.compatibility_cnsa1, 0);
        assert_eq!(record.compatibility_cnsa2, 0);
        assert_eq!(record.handshake_duration_us, 0);
        assert_eq!(record.handshake_compute_us, 0);
    }
}
