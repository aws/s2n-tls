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
    label::{State, metric_label},
    parsing::ClientHelloSupportedParameters,
    static_lists::{
        self, CIPHERS_AVAILABLE_IN_S2N, GROUPS_AVAILABLE_IN_S2N,
        SIGNATURE_SCHEMES_AVAILABLE_IN_S2N, TlsParam, ToStaticString, VERSIONS_AVAILABLE_IN_S2N,
    },
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

    negotiated_protocols: [AtomicU64; PROTOCOL_COUNT],
    negotiated_ciphers: [AtomicU64; CIPHER_COUNT],
    negotiated_groups: [AtomicU64; GROUP_COUNT],
    negotiated_signatures: [AtomicU64; SIGNATURE_COUNT],

    // we do not attempt to detect supported parameters for SSLv2 formatted client
    // hellos
    sslv2_client_hello: AtomicU64,
    supported_protocols: [AtomicU64; PROTOCOL_COUNT],
    supported_ciphers: [AtomicU64; CIPHER_COUNT],
    supported_groups: [AtomicU64; GROUP_COUNT],
    supported_signatures: [AtomicU64; SIGNATURE_COUNT],

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

fn relaxed_freeze<const T: usize>(array: &[AtomicU64; T]) -> [u64; T] {
    array
        .each_ref()
        .map(|counter| counter.load(Ordering::Relaxed))
}

impl HandshakeRecordInProgress {
    pub fn new(exporter: std::sync::mpsc::Sender<FrozenHandshakeRecord>) -> Self {
        // default is not implemented for arrays this large
        let negotiated_ciphers = [0; CIPHER_COUNT].map(|_| AtomicU64::default());
        let supported_ciphers = [0; CIPHER_COUNT].map(|_| AtomicU64::default());
        Self {
            handshake_count: Default::default(),

            negotiated_groups: Default::default(),
            negotiated_ciphers,
            negotiated_protocols: Default::default(),
            negotiated_signatures: Default::default(),

            sslv2_client_hello: Default::default(),
            supported_groups: Default::default(),
            supported_ciphers,
            supported_protocols: Default::default(),
            supported_signatures: Default::default(),

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

        conn.signature_scheme()
            .and_then(|name| TlsParam::SignatureScheme.description_to_index(name))
            .and_then(|index| self.negotiated_signatures.get(index))
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));

        if conn.client_hello_is_sslv2()? {
            self.sslv2_client_hello.fetch_add(1, Ordering::Relaxed);
        } else {
            let supported_parameter = ClientHelloSupportedParameters::new(conn.client_hello()?);

            supported_parameter
                .supported_versions()?
                .iter()
                .filter_map(|version| version.known_description())
                .filter_map(|description| TlsParam::Version.description_to_index(description))
                .filter_map(|index| self.supported_protocols.get(index))
                .for_each(|counter| {
                    counter.fetch_add(1, Ordering::Relaxed);
                });

            supported_parameter
                .supported_ciphers()?
                .iter()
                .filter_map(|cipher| cipher.known_description())
                .filter_map(|description| TlsParam::Cipher.description_to_index(description))
                .filter_map(|index| self.supported_ciphers.get(index))
                .for_each(|counter| {
                    counter.fetch_add(1, Ordering::Relaxed);
                });

            if let Some(supported_groups) = supported_parameter.supported_groups()? {
                supported_groups
                    .iter()
                    .filter_map(|group| group.known_description())
                    .filter_map(|description| TlsParam::Group.description_to_index(description))
                    .filter_map(|index| self.supported_groups.get(index))
                    .for_each(|counter| {
                        counter.fetch_add(1, Ordering::Relaxed);
                    });
            }

            if let Some(supported_sigs) = supported_parameter.supported_signatures()? {
                supported_sigs
                    .iter()
                    .filter_map(|signature| signature.known_description())
                    .filter_map(|description| {
                        TlsParam::SignatureScheme.description_to_index(description)
                    })
                    .filter_map(|index| self.supported_signatures.get(index))
                    .for_each(|counter| {
                        counter.fetch_add(1, Ordering::Relaxed);
                    });
            }

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
            negotiated_protocols: relaxed_freeze(&self.negotiated_protocols),
            negotiated_ciphers: relaxed_freeze(&self.negotiated_ciphers),
            negotiated_groups: relaxed_freeze(&self.negotiated_groups),
            negotiated_signatures: relaxed_freeze(&self.negotiated_signatures),

            sslv2_client_hello: self.sslv2_client_hello.load(Ordering::Relaxed),
            supported_protocols: relaxed_freeze(&self.supported_protocols),
            supported_ciphers: relaxed_freeze(&self.supported_ciphers),
            supported_groups: relaxed_freeze(&self.supported_groups),
            supported_signatures: relaxed_freeze(&self.supported_signatures),

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

use serde_big_array::BigArray;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct FrozenHandshakeRecord {
    freeze_time: SystemTime,

    pub(crate) handshake_count: u64,

    negotiated_protocols: [u64; PROTOCOL_COUNT],
    #[serde(with = "BigArray")]
    negotiated_ciphers: [u64; CIPHER_COUNT],
    negotiated_groups: [u64; GROUP_COUNT],
    negotiated_signatures: [u64; SIGNATURE_COUNT],

    sslv2_client_hello: u64,
    supported_protocols: [u64; PROTOCOL_COUNT],
    #[serde(with = "BigArray")]
    supported_ciphers: [u64; CIPHER_COUNT],
    supported_groups: [u64; GROUP_COUNT],
    supported_signatures: [u64; SIGNATURE_COUNT],

    compatibility_general20251201: u64,
    compatibility_fips20251201: u64,
    compatibility_cnsa1: u64,
    compatibility_cnsa2: u64,

    handshake_duration_us: u64,
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
            negotiated_protocols: [0; PROTOCOL_COUNT],
            negotiated_ciphers: [0; CIPHER_COUNT],
            negotiated_groups: [0; GROUP_COUNT],
            negotiated_signatures: [0; SIGNATURE_COUNT],
            sslv2_client_hello: 0,
            supported_protocols: [0; PROTOCOL_COUNT],
            supported_ciphers: [0; CIPHER_COUNT],
            supported_groups: [0; GROUP_COUNT],
            supported_signatures: [0; SIGNATURE_COUNT],
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

        for (list, parameter, state) in [
            (
                self.negotiated_protocols.as_slice(),
                TlsParam::Version,
                State::Negotiated,
            ),
            (
                self.negotiated_ciphers.as_slice(),
                TlsParam::Cipher,
                State::Negotiated,
            ),
            (
                self.negotiated_groups.as_slice(),
                TlsParam::Group,
                State::Negotiated,
            ),
            (
                self.negotiated_signatures.as_slice(),
                TlsParam::SignatureScheme,
                State::Negotiated,
            ),
            (
                self.supported_protocols.as_slice(),
                TlsParam::Version,
                State::Supported,
            ),
            (
                self.supported_ciphers.as_slice(),
                TlsParam::Cipher,
                State::Supported,
            ),
            (
                self.supported_groups.as_slice(),
                TlsParam::Group,
                State::Supported,
            ),
            (
                self.supported_signatures.as_slice(),
                TlsParam::SignatureScheme,
                State::Supported,
            ),
        ] {
            list.iter()
                .enumerate()
                .filter(|(_index, count)| **count > 0)
                .filter_map(
                    |(index, count)| match parameter.index_to_description(index) {
                        Some(name) => Some((name, count)),
                        None => {
                            debug_assert!(false, "failed to get name for {index} of {parameter:?}");
                            None
                        }
                    },
                )
                .for_each(|(name, count)| {
                    let label = metric_label(name, parameter, state);
                    writer.value(label, count);
                });
        }

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

        let expected_sig = result.client.signature_scheme().unwrap().to_owned();
        let expected_index = TlsParam::SignatureScheme
            .description_to_index(expected_sig.as_str())
            .unwrap();
        assert_eq!(record.negotiated_signatures[expected_index], 1);
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

        let expected_version: Vec<usize> = EXPECTED_VERSIONS
            .iter()
            .map(|description| TlsParam::Version.description_to_index(description).unwrap())
            .collect();
        let expected_ciphers: Vec<usize> = EXPECTED_CIPHERS
            .iter()
            .map(|description| TlsParam::Cipher.description_to_index(description).unwrap())
            .collect();
        let expected_groups: Vec<usize> = EXPECTED_GROUPS
            .iter()
            .map(|description| TlsParam::Group.description_to_index(description).unwrap())
            .collect();
        let expected_sigs: Vec<usize> = EXPECTED_SIGS
            .iter()
            .map(|description| {
                TlsParam::SignatureScheme
                    .description_to_index(description)
                    .unwrap()
            })
            .collect();

        for (index, count) in record.supported_protocols.iter().enumerate() {
            let param = TlsParam::Version.index_to_description(index).unwrap();
            if expected_version.contains(&index) {
                assert_eq!(*count, 1, "{param} count is {count}, not one");
            } else {
                assert_eq!(*count, 0, "{param} count is {count}, not zero");
            }
        }

        for (index, count) in record.supported_ciphers.iter().enumerate() {
            let param = TlsParam::Cipher.index_to_description(index).unwrap();
            if expected_ciphers.contains(&index) {
                assert_eq!(*count, 1, "{param} count is {count}, not one");
            } else {
                assert_eq!(*count, 0, "{param} count is {count}, not zero");
            }
        }

        for (index, count) in record.supported_groups.iter().enumerate() {
            let param = TlsParam::Group.index_to_description(index).unwrap();
            if expected_groups.contains(&index) {
                assert_eq!(*count, 1, "{param} count is {count}, not one");
            } else {
                assert_eq!(*count, 0, "{param} count is {count}, not zero");
            }
        }

        for (index, count) in record.supported_signatures.iter().enumerate() {
            let param = TlsParam::SignatureScheme
                .index_to_description(index)
                .unwrap();
            if expected_sigs.contains(&index) {
                assert_eq!(*count, 1, "{param} count is {count}, not one");
            } else {
                assert_eq!(*count, 0, "{param} count is {count}, not zero");
            }
        }
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
        assert_eq!(record.negotiated_ciphers.iter().sum::<u64>(), 3);
        assert_eq!(record.negotiated_groups.iter().sum::<u64>(), 3);
        assert_eq!(record.negotiated_signatures.iter().sum::<u64>(), 3);
        assert_eq!(record.negotiated_protocols.iter().sum::<u64>(), 3);
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
}
