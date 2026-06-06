// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

use s2n_tls_metrics_schema::{
    record::FrozenHandshakeRecord,
    static_lists::{
        CIPHER_COUNT, Cipher, GROUP_COUNT, Group, PROTOCOL_COUNT, SIGNATURE_COUNT, Signature,
        Version,
    },
};

use crate::{
    bounded_set::BoundedStringSet,
    compatibility::{Cnsa1, Cnsa2, Fips20251201, General20251201, TlsProfile},
    counter::Counter,
    detector::SyntheticTrafficDetector,
    parsing::ClientHelloSupportedParameters,
};

fn protocol_version_to_iana(v: s2n_tls::enums::Version) -> Option<Version> {
    let iana = match v {
        s2n_tls::enums::Version::SSLV3 => 0x0300u16,
        s2n_tls::enums::Version::TLS10 => 0x0301,
        s2n_tls::enums::Version::TLS11 => 0x0302,
        s2n_tls::enums::Version::TLS12 => 0x0303,
        s2n_tls::enums::Version::TLS13 => 0x0304,
        _ => return None,
    };
    Some(Version(s2n_codec::zerocopy::U16::new(iana)))
}

/// The HandshakeRecordInProgress stores the in-flight counters for handshake
/// information - e.g. negotiated parameters.
#[derive(Debug)]
pub(crate) struct HandshakeRecordInProgress {
    /// This is used to send a frozen version back to the Aggregator, after which
    /// point it can be exported. This is only used in the drop impl.
    exporter: std::sync::mpsc::Sender<FrozenHandshakeRecord>,

    security_policies: BoundedStringSet,

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

    /// Number of handshakes flagged by the configured
    /// [`SyntheticTrafficDetector`]. Synthetic handshakes are excluded from
    /// every other counter on this record (including `handshake_count`).
    synthetic_traffic_count: AtomicU64,
}

impl HandshakeRecordInProgress {
    pub fn new(exporter: std::sync::mpsc::Sender<FrozenHandshakeRecord>) -> Self {
        Self {
            security_policies: Default::default(),
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
            synthetic_traffic_count: Default::default(),
            exporter,
        }
    }

    pub fn update(
        &self,
        conn: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
        detector: Option<&dyn SyntheticTrafficDetector>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client_hello = conn.client_hello()?;

        // Run the detector first, on every handshake (including SSLv2).
        // Synthetic handshakes contribute ONLY to `synthetic_traffic_count`;
        // every other counter (including `handshake_count`) reflects real
        // traffic only, so consumers can read each metric directly without
        // post-processing.
        if let Some(detector) = detector {
            if detector.is_synthetic(client_hello) {
                self.synthetic_traffic_count.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        }

        self.handshake_count.fetch_add(1, Ordering::Relaxed);

        self.security_policies.record(event.security_policy_label());

        if let Some(sig) = conn.signature_scheme().and_then(|s| s.parse().ok()) {
            self.negotiated_signatures.increment(&sig);
        }

        if conn.client_hello_is_sslv2()? {
            self.sslv2_client_hello.fetch_add(1, Ordering::Relaxed);
        } else {
            let supported_parameter = ClientHelloSupportedParameters::new(client_hello)?;

            supported_parameter
                .supported_versions()
                .iter()
                .for_each(|version| self.supported_protocols.increment(version));

            supported_parameter
                .supported_ciphers()
                .iter()
                .for_each(|cipher| self.supported_ciphers.increment(cipher));

            supported_parameter
                .supported_groups()
                .iter()
                .flat_map(|groups| groups.iter())
                .for_each(|group| self.supported_groups.increment(group));

            supported_parameter
                .supported_signatures()
                .iter()
                .flat_map(|sigs| sigs.iter())
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

        if let Some(version) = protocol_version_to_iana(event.protocol_version()) {
            self.negotiated_protocols.increment(&version);
        }

        if let Some(cipher) = Cipher::from_openssl_name(event.cipher()) {
            self.negotiated_ciphers.increment(&cipher);
        }

        if let Some(group) = event.group().and_then(|g| g.parse().ok()) {
            self.negotiated_groups.increment(&group);
        }

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
            synthetic_traffic_count: self.synthetic_traffic_count.load(Ordering::Relaxed),
            security_policies: self.security_policies.freeze(),
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

#[cfg(test)]
mod tests {
    use crate::test_utils::{ARBITRARY_POLICY_1, TestEndpoint};
    use s2n_tls_metrics_schema::{
        counter::FrozenCounter,
        static_lists::{Cipher, FiniteCounter},
    };

    use super::*;

    #[test]
    fn record_contents_negotiated_parameters() {
        let endpoint = TestEndpoint::new();

        let result = endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let record = &records[0].as_schema().handshake;

        assert_eq!(record.handshake_count, 1);
        assert_eq!(
            record
                .negotiated_ciphers
                .iter_non_zero()
                .map(|(_, _, c)| c)
                .sum::<u64>(),
            1
        );
        assert_eq!(
            record
                .negotiated_groups
                .iter_non_zero()
                .map(|(_, _, c)| c)
                .sum::<u64>(),
            1
        );
        assert_eq!(
            record
                .negotiated_signatures
                .iter_non_zero()
                .map(|(_, _, c)| c)
                .sum::<u64>(),
            1
        );
        assert_eq!(
            record
                .negotiated_protocols
                .iter_non_zero()
                .map(|(_, _, c)| c)
                .sum::<u64>(),
            1
        );

        let expected_version_element =
            protocol_version_to_iana(result.client.actual_protocol_version().unwrap()).unwrap();
        let slot = expected_version_element.slot_from_key().unwrap();
        assert_eq!(record.negotiated_protocols.slots()[slot], 1);

        let expected_cipher = result.client.cipher_suite().unwrap().to_owned();
        let expected_cipher_element = Cipher::from_openssl_name(expected_cipher.as_str()).unwrap();
        let slot = expected_cipher_element.slot_from_key().unwrap();
        assert_eq!(record.negotiated_ciphers.slots()[slot], 1);

        let expected_group = result
            .client
            .selected_key_exchange_group()
            .unwrap()
            .to_owned();
        let expected_group_element: Group = expected_group.parse().unwrap();
        let slot = expected_group_element.slot_from_key().unwrap();
        assert_eq!(record.negotiated_groups.slots()[slot], 1);

        let expected_sig = result.client.signature_scheme().unwrap().to_owned();
        let expected_sig_element: Signature = expected_sig.parse().unwrap();
        let slot = expected_sig_element.slot_from_key().unwrap();
        assert_eq!(record.negotiated_signatures.slots()[slot], 1);
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
        let record = &records[0].as_schema().handshake;

        fn assert_supported_matches<const N: usize, T>(
            counter: &FrozenCounter<N, T>,
            expected: &[&str],
        ) where
            T: FiniteCounter<N> + std::fmt::Display + std::str::FromStr<Err = ()>,
        {
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

            for (slot, &count) in counter.slots().iter().enumerate() {
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
        let record = &records[0].as_schema().handshake;

        assert_eq!(record.handshake_count, 3);
        assert_eq!(
            record
                .negotiated_ciphers
                .iter_non_zero()
                .map(|(_, _, c)| c)
                .sum::<u64>(),
            3
        );
        assert_eq!(
            record
                .negotiated_groups
                .iter_non_zero()
                .map(|(_, _, c)| c)
                .sum::<u64>(),
            3
        );
        assert_eq!(
            record
                .negotiated_signatures
                .iter_non_zero()
                .map(|(_, _, c)| c)
                .sum::<u64>(),
            3
        );
        assert_eq!(
            record
                .negotiated_protocols
                .iter_non_zero()
                .map(|(_, _, c)| c)
                .sum::<u64>(),
            3
        );
    }

    /// A record with no handshakes should be entirely empty/default.
    #[test]
    fn empty_record() {
        let endpoint = TestEndpoint::new();

        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let mut record = records[0].as_schema().handshake.clone();

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
        let record = &records[0].as_schema().handshake;

        assert_eq!(record.compatibility_general20251201, 1);
        assert_eq!(record.compatibility_fips20251201, 1);
        assert_eq!(record.compatibility_cnsa1, 1);
        assert_eq!(record.compatibility_cnsa2, 0);
    }

    #[test]
    fn record_contents_security_policies() {
        use s2n_tls::security::Policy;
        use s2n_tls_metrics_schema::bounded_set::FrozenBoundedStringSet;
        use std::ffi::CStr;

        // a single handshake -> a single security policy
        {
            let endpoint = TestEndpoint::new();
            endpoint.client_handshake(&ARBITRARY_POLICY_1);
            endpoint.subscriber.finish_record();
            let records = endpoint.sink.records.lock().unwrap();
            let policies = &records[0].as_schema().handshake.security_policies;
            match policies {
                FrozenBoundedStringSet::Entries(set) => {
                    assert_eq!(set.len(), 1);
                    assert!(set.contains("default_tls13"));
                }
                FrozenBoundedStringSet::TooMany => panic!("expected Entires"),
            }
        }

        // multiple handshakes shifting between two policies -> two policies recorded
        {
            let endpoint = TestEndpoint::new();
            endpoint.client_handshake(&ARBITRARY_POLICY_1);

            let policy_b = Policy::from_version("20240501").unwrap();
            let client_config = s2n_tls::testing::build_config(&ARBITRARY_POLICY_1).unwrap();
            let mut pair =
                s2n_tls::testing::TestPair::from_configs(&client_config, &endpoint.server_config);
            pair.server.set_security_policy(&policy_b).unwrap();
            pair.handshake().unwrap();

            endpoint.subscriber.finish_record();
            let records = endpoint.sink.records.lock().unwrap();
            let policies = &records[0].as_schema().handshake.security_policies;
            match policies {
                FrozenBoundedStringSet::Entries(set) => {
                    assert_eq!(set.len(), 2);
                }
                FrozenBoundedStringSet::TooMany => panic!("expected Entires"),
            }
        }

        // more than 10 security policies -> TOO_MANY is recorded
        {
            let endpoint = TestEndpoint::new();
            let client_config = s2n_tls::testing::build_config(&ARBITRARY_POLICY_1).unwrap();

            let policies: Vec<Policy> = s2n_tls_sys_internal::security_policy_table()
                .iter()
                .filter_map(|entry| {
                    let name = unsafe { CStr::from_ptr(entry.version) }.to_str().ok()?;
                    Policy::from_version(name).ok()
                })
                .take(11)
                .collect();
            assert!(policies.len() > 10, "not enough compatible policies found");

            for policy in &policies {
                let mut pair = s2n_tls::testing::TestPair::from_configs(
                    &client_config,
                    &endpoint.server_config,
                );
                pair.server.set_security_policy(policy).unwrap();
                pair.handshake().unwrap();
            }

            endpoint.subscriber.finish_record();
            let records = endpoint.sink.records.lock().unwrap();
            assert_eq!(
                records[0].as_schema().handshake.security_policies,
                FrozenBoundedStringSet::TooMany
            );
        }
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
        let single_handshake = &records[0].as_schema().handshake;

        assert!(single_handshake.handshake_compute_us <= single_handshake.handshake_duration_us);
        drop(records);

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let single_handshake = &records[0].as_schema().handshake;
        let multiple_handshakes = &records[1].as_schema().handshake;

        assert!(
            multiple_handshakes.handshake_compute_us <= multiple_handshakes.handshake_duration_us
        );

        assert!(single_handshake.handshake_compute_us < multiple_handshakes.handshake_compute_us);
        assert!(single_handshake.handshake_duration_us < multiple_handshakes.handshake_duration_us);
    }
}
