// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

use s2n_tls::{connection::Connection, error::Error as S2NError, events::HandshakeSuccess};
use s2n_tls_metrics_schema::{
    record::FrozenHandshakeRecord,
    static_lists::{
        Alert, CERT_KEY_COUNT, CERT_SIG_COUNT, CIPHER_COUNT, CertKeyType, CertSignatureAlgorithm,
        Cipher, ClientIssue, DEFINED_ALERTS_COUNT, GROUP_COUNT, Group, PROTOCOL_COUNT,
        SIGNATURE_COUNT, Signature, Version,
    },
};

use crate::{
    bounded_set::BoundedStringSet,
    client_issue::has_issue,
    compatibility::{Cnsa1, Cnsa2, Fips20251201, General20251201, TlsProfile},
    counter::Counter,
    detector::SyntheticTrafficDetector,
    parsing::{self, ClientHelloSupportedParameters},
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

pub(crate) struct NegotiatedParameters {
    pub version: Version,
    pub cipher: Cipher,
    pub group: Option<Group>,
    pub signature: Option<Signature>,
}

impl NegotiatedParameters {
    fn from_connection(success: &HandshakeSuccess, conn: &Connection) -> Result<Self, S2NError> {
        let version = match protocol_version_to_iana(success.protocol_version()) {
            Some(version) => version,
            None => {
                tracing::error!("{:?} not a recognized protocol", success.protocol_version());
                return Err(S2NError::application("unrecognized parameter".into()));
            }
        };

        let cipher = match Cipher::from_openssl_name(success.cipher()) {
            Some(cipher) => cipher,
            None => {
                tracing::error!("{:?} not a recognized cipher", success.cipher());
                return Err(S2NError::application("unrecognized parameter".into()));
            }
        };

        let group = success.group().and_then(|g| g.parse().ok());
        let signature = conn.signature_scheme().and_then(|s| s.parse().ok());

        Ok(Self {
            version,
            cipher,
            group,
            signature,
        })
    }
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
    handshake_success_count: AtomicU64,

    /// the total number of failed handshakes
    handshake_failure_count: AtomicU64,
    alerts: Counter<DEFINED_ALERTS_COUNT, Alert>,

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

    // chain counters will increment for both the ICA and the CA
    server_leaf_cert_key: Counter<CERT_KEY_COUNT, CertKeyType>,
    server_leaf_cert_sig: Counter<CERT_SIG_COUNT, CertSignatureAlgorithm>,
    server_chain_cert_key: Counter<CERT_KEY_COUNT, CertKeyType>,
    server_chain_cert_sig: Counter<CERT_SIG_COUNT, CertSignatureAlgorithm>,
    client_leaf_cert_key: Counter<CERT_KEY_COUNT, CertKeyType>,
    client_leaf_cert_sig: Counter<CERT_SIG_COUNT, CertSignatureAlgorithm>,
    client_chain_cert_key: Counter<CERT_KEY_COUNT, CertKeyType>,
    client_chain_cert_sig: Counter<CERT_SIG_COUNT, CertSignatureAlgorithm>,
    /// indicates a parsing error in the metrics subscriber der codec
    server_cert_parsing_failure: AtomicU64,
    client_cert_parsing_failure: AtomicU64,

    compatibility_general20251201: AtomicU64,
    compatibility_fips20251201: AtomicU64,
    compatibility_cnsa1: AtomicU64,
    compatibility_cnsa2: AtomicU64,

    client_issue: Counter<{ ClientIssue::COUNT }, ClientIssue>,

    /// sum of handshake duration, including network latency and waiting
    ///
    /// To get the average, divide this by handshake_success_count.
    handshake_duration_us: AtomicU64,
    /// sum of handshake compute
    ///
    /// To get the average, divide this by handshake_success_count.
    handshake_compute_us: AtomicU64,

    /// Number of handshakes flagged by the configured
    /// [`SyntheticTrafficDetector`]. Synthetic handshakes are excluded from
    /// every other counter on this record (including `handshake_success_count`).
    synthetic_traffic_count: AtomicU64,

    /// Number of handshakes where an internal error prevented the metrics
    /// subscriber from fully recording metrics.
    internal_failure: AtomicU64,
}

impl HandshakeRecordInProgress {
    pub fn new(exporter: std::sync::mpsc::Sender<FrozenHandshakeRecord>) -> Self {
        Self {
            security_policies: Default::default(),
            handshake_success_count: Default::default(),
            handshake_failure_count: Default::default(),
            alerts: Counter::new(),

            negotiated_groups: Counter::new(),
            negotiated_ciphers: Counter::new(),
            negotiated_protocols: Counter::new(),
            negotiated_signatures: Counter::new(),

            sslv2_client_hello: Default::default(),
            supported_groups: Counter::new(),
            supported_ciphers: Counter::new(),
            supported_protocols: Counter::new(),
            supported_signatures: Counter::new(),

            server_leaf_cert_key: Counter::new(),
            server_leaf_cert_sig: Counter::new(),
            server_chain_cert_key: Counter::new(),
            server_chain_cert_sig: Counter::new(),
            client_leaf_cert_key: Counter::new(),
            client_leaf_cert_sig: Counter::new(),
            client_chain_cert_key: Counter::new(),
            client_chain_cert_sig: Counter::new(),
            server_cert_parsing_failure: Default::default(),
            client_cert_parsing_failure: Default::default(),

            compatibility_general20251201: AtomicU64::default(),
            compatibility_fips20251201: AtomicU64::default(),
            compatibility_cnsa1: AtomicU64::default(),
            compatibility_cnsa2: AtomicU64::default(),

            client_issue: Counter::new(),

            handshake_duration_us: Default::default(),
            handshake_compute_us: Default::default(),
            synthetic_traffic_count: Default::default(),
            internal_failure: Default::default(),
            exporter,
        }
    }

    // This method should always be infallible. If there is an internal error
    // e.g. being unable to retrieve something from s2n-tls, you should increment
    // the internal_failure metric and log the error with `tracing::error!`
    pub fn update(
        &self,
        conn: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
        detector: Option<&dyn SyntheticTrafficDetector>,
    ) {
        // client_hello is only available on the server side of the connection.
        // Even on the server side, the client hello may not be populated if the
        // handshake failed before the client hello was fully received/parsed.
        let client_hello = if conn.mode() == s2n_tls::enums::Mode::Server {
            conn.client_hello().ok()
        } else {
            None
        };

        // Run the detector first, on every handshake (including SSLv2).
        // Synthetic handshakes contribute ONLY to `synthetic_traffic_count`;
        // every other counter (including `handshake_success_count`) reflects real
        // traffic only, so consumers can read each metric directly without
        // post-processing.
        if let Some(detector) = detector {
            if let Some(client_hello) = client_hello {
                if detector.is_synthetic(client_hello) {
                    self.synthetic_traffic_count.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }

        let success = match event.result() {
            s2n_tls::events::HandshakeResult::Failure(_) => {
                self.handshake_failure_count.fetch_add(1, Ordering::Relaxed);
                let alert = conn.alert().map(Alert);
                if let Some(alert) = alert {
                    self.alerts.increment(&alert);
                }
                return;
            }
            s2n_tls::events::HandshakeResult::Success(s) => {
                self.handshake_success_count.fetch_add(1, Ordering::Relaxed);
                s
            }
        };

        // if it was a successful handshake and we're a server, then the client
        // hello should always be available. If not, increment an internal failure
        // metric and give up.
        if conn.mode() == s2n_tls::enums::Mode::Server && client_hello.is_none() {
            tracing::error!(
                "client hello unavailable after successful handshake: {:?}",
                conn.client_hello().err()
            );
            self.internal_failure.fetch_add(1, Ordering::Relaxed);
            return;
        }

        self.security_policies.record(event.security_policy_label());

        // populate negotiated parameters
        let negotiated = match NegotiatedParameters::from_connection(&success, conn) {
            Ok(negotiated) => negotiated,
            Err(_) => {
                // error is already logged in NegotiatedParameters::from_connection
                self.internal_failure.fetch_add(1, Ordering::Relaxed);
                // this connection is in a bad state, don't record any more telemetry
                return;
            }
        };
        self.negotiated_protocols.increment(&negotiated.version);
        self.negotiated_ciphers.increment(&negotiated.cipher);
        if let Some(group) = negotiated.group {
            self.negotiated_groups.increment(&group);
        }
        if let Some(sig) = negotiated.signature {
            self.negotiated_signatures.increment(&sig);
        }

        let supported_parameters = if let Some(client_hello) = client_hello {
            match (
                conn.client_hello_is_sslv2(),
                ClientHelloSupportedParameters::new(client_hello),
            ) {
                (Ok(true), _) => {
                    // we don't support parsing supported parameters from SSLv2
                    // client hellos because they have a different structure
                    self.sslv2_client_hello.fetch_add(1, Ordering::Relaxed);
                    None
                }
                (Ok(false), Ok(supported_parameter)) => {
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
                    Some(supported_parameter)
                }
                (Err(e), _) => {
                    // never expected to fail: a failure means the handshake
                    // succeeded without s2n-tls knowing whether or not it was
                    // an SSLv2 client hello
                    tracing::error!("failed to determine sslv2 client hello status: {e}");
                    self.internal_failure.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                (_, Err(e)) => {
                    // never expected to fail: a failure means that s2n-tls
                    // considered the client hello well-formed, but our parser
                    // didn't
                    tracing::error!("failed to parse client hello supported parameters: {e}");
                    self.internal_failure.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        } else {
            None
        };

        // populate client issues
        if let Some(supported) = supported_parameters {
            ClientIssue::MEMBERS
                .into_iter()
                .filter(|issue| has_issue(*issue, &negotiated, &supported))
                .for_each(|issue| self.client_issue.increment(&issue));
        }

        // populate cert metrics
        {
            fn record_chain_metrics<'a>(
                mut certs: impl Iterator<
                    Item = Result<s2n_tls::cert_chain::Certificate<'a>, s2n_tls::error::Error>,
                >,
                leaf_key: &Counter<CERT_KEY_COUNT, CertKeyType>,
                leaf_sig: &Counter<CERT_SIG_COUNT, CertSignatureAlgorithm>,
                chain_key: &Counter<CERT_KEY_COUNT, CertKeyType>,
                chain_sig: &Counter<CERT_SIG_COUNT, CertSignatureAlgorithm>,
                parse_failures: &AtomicU64,
            ) {
                if let Some(Ok(cert)) = certs.next() {
                    if let Ok(der) = cert.der() {
                        match parsing::cert::parse(der) {
                            Ok(c) => {
                                leaf_key.increment(&c.key_type);
                                leaf_sig.increment(&c.signature);
                            }
                            Err(_) => {
                                parse_failures.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                for cert in certs.flatten() {
                    if let Ok(der) = cert.der() {
                        match parsing::cert::parse(der) {
                            Ok(c) => {
                                chain_key.increment(&c.key_type);
                                chain_sig.increment(&c.signature);
                            }
                            Err(_) => {
                                parse_failures.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }

            // selected_cert() is the local cert; peer_cert_chain() is the remote cert.
            // Map to server/client labels based on connection mode.
            let (server_cert, client_cert) = match conn.mode() {
                s2n_tls::enums::Mode::Server => (conn.selected_cert(), conn.peer_cert_chain().ok()),
                s2n_tls::enums::Mode::Client => (conn.peer_cert_chain().ok(), conn.selected_cert()),
            };

            if let Some(cert) = server_cert {
                record_chain_metrics(
                    cert.iter(),
                    &self.server_leaf_cert_key,
                    &self.server_leaf_cert_sig,
                    &self.server_chain_cert_key,
                    &self.server_chain_cert_sig,
                    &self.server_cert_parsing_failure,
                );
            }

            if let Some(cert) = client_cert {
                record_chain_metrics(
                    cert.iter(),
                    &self.client_leaf_cert_key,
                    &self.client_leaf_cert_sig,
                    &self.client_chain_cert_key,
                    &self.client_chain_cert_sig,
                    &self.client_cert_parsing_failure,
                );
            }
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
            handshake_success_count: self.handshake_success_count.load(Ordering::Relaxed),
            handshake_failure_count: self.handshake_failure_count.load(Ordering::Relaxed),
            alerts: self.alerts.freeze(),
            negotiated_protocols: self.negotiated_protocols.freeze(),
            negotiated_ciphers: self.negotiated_ciphers.freeze(),
            negotiated_groups: self.negotiated_groups.freeze(),
            negotiated_signatures: self.negotiated_signatures.freeze(),

            sslv2_client_hello: self.sslv2_client_hello.load(Ordering::Relaxed),
            supported_protocols: self.supported_protocols.freeze(),
            supported_ciphers: self.supported_ciphers.freeze(),
            supported_groups: self.supported_groups.freeze(),
            supported_signatures: self.supported_signatures.freeze(),

            server_leaf_cert_key: self.server_leaf_cert_key.freeze(),
            server_leaf_cert_sig: self.server_leaf_cert_sig.freeze(),
            server_chain_cert_key: self.server_chain_cert_key.freeze(),
            server_chain_cert_sig: self.server_chain_cert_sig.freeze(),
            client_leaf_cert_key: self.client_leaf_cert_key.freeze(),
            client_leaf_cert_sig: self.client_leaf_cert_sig.freeze(),
            client_chain_cert_key: self.client_chain_cert_key.freeze(),
            client_chain_cert_sig: self.client_chain_cert_sig.freeze(),
            server_cert_parsing_failure: self.server_cert_parsing_failure.load(Ordering::Relaxed),
            client_cert_parsing_failure: self.client_cert_parsing_failure.load(Ordering::Relaxed),

            compatibility_general20251201: self
                .compatibility_general20251201
                .load(Ordering::Relaxed),
            compatibility_fips20251201: self.compatibility_fips20251201.load(Ordering::Relaxed),
            compatibility_cnsa1: self.compatibility_cnsa1.load(Ordering::Relaxed),
            compatibility_cnsa2: self.compatibility_cnsa2.load(Ordering::Relaxed),

            client_issues: self.client_issue.freeze(),

            handshake_duration_us: self.handshake_duration_us.load(Ordering::Relaxed),
            handshake_compute_us: self.handshake_compute_us.load(Ordering::Relaxed),
            synthetic_traffic_count: self.synthetic_traffic_count.load(Ordering::Relaxed),
            internal_failure: self.internal_failure.load(Ordering::Relaxed),
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

        assert_eq!(record.handshake_success_count, 1);
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

        assert_eq!(record.handshake_success_count, 3);
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
                FrozenBoundedStringSet::TooMany => panic!("expected Entries"),
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
                FrozenBoundedStringSet::TooMany => panic!("expected Entries"),
            }
        }

        // more than 10 security policies -> TOO_MANY is recorded
        {
            let endpoint = TestEndpoint::new();
            let client_config = s2n_tls::testing::build_config(&ARBITRARY_POLICY_1).unwrap();

            let policies: Vec<Policy> = {
                let mut seen = std::collections::HashSet::new();
                let mut result = Vec::new();
                for entry in s2n_tls_sys_internal::security_policy_table() {
                    // we need unique security policies (e.g. unique security policy
                    // pointers)
                    if !seen.insert(entry.security_policy as usize) {
                        continue;
                    }
                    let name = unsafe { CStr::from_ptr(entry.version) }.to_str().unwrap();
                    result.push(Policy::from_version(name).unwrap());
                    if result.len() > BoundedStringSet::MAX_STORAGE {
                        break;
                    }
                }
                result
            };
            assert_eq!(policies.len(), BoundedStringSet::MAX_STORAGE + 1);

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

    /// Helper: performs an mTLS handshake using distinct cert types for server
    /// (RSA 4096 / SHA384) and client (ECDSA P384 / SHA384) so the test can
    /// distinguish which cert ended up in which record field.
    mod mtls_helper {
        use crate::{AggregatedMetricsSubscriber, Attribution, test_utils::VecSink};
        use s2n_tls::{
            enums::ClientAuthType,
            security::DEFAULT_TLS13,
            testing::{CertKeyPair, TestPair},
        };

        pub(super) struct MtlsEndpoint {
            pub subscriber: AggregatedMetricsSubscriber<VecSink>,
            pub sink: VecSink,
            pub client_config: s2n_tls::config::Config,
            pub server_config: s2n_tls::config::Config,
        }

        /// Server cert: RSA 4096 / SHA384
        fn server_keypair() -> CertKeyPair {
            CertKeyPair::from_path(
                "permutations/rsae_pkcs_4096_sha384/",
                "server-chain",
                "server-key",
                "ca-cert",
            )
        }

        /// Client cert: ECDSA P384 / SHA384
        fn client_keypair() -> CertKeyPair {
            CertKeyPair::from_path(
                "permutations/ec_ecdsa_p384_sha384/",
                "client-cert",
                "client-key",
                "ca-cert",
            )
        }

        /// Build an mTLS endpoint with the subscriber on the server side.
        pub(super) fn server_endpoint() -> MtlsEndpoint {
            let sink = VecSink::new();
            let attribution = Attribution {
                service: "test".to_owned(),
                resource: "test".to_owned(),
                component: "test".to_owned(),
            };
            let subscriber = AggregatedMetricsSubscriber::new(sink.clone(), attribution);

            let server_keypair = server_keypair();
            let client_keypair = client_keypair();

            let server_config = {
                let mut c = s2n_tls::config::Builder::new();
                c.set_security_policy(&DEFAULT_TLS13)
                    .unwrap()
                    .load_pem(server_keypair.cert(), server_keypair.key())
                    .unwrap()
                    .trust_pem(client_keypair.ca_cert())
                    .unwrap()
                    .set_client_auth_type(ClientAuthType::Required)
                    .unwrap()
                    .set_event_subscriber(subscriber.clone())
                    .unwrap();
                c.build().unwrap()
            };

            let client_config = {
                let mut c = s2n_tls::config::Builder::new();
                c.set_security_policy(&DEFAULT_TLS13)
                    .unwrap()
                    .load_pem(client_keypair.cert(), client_keypair.key())
                    .unwrap()
                    .trust_pem(server_keypair.ca_cert())
                    .unwrap()
                    .with_system_certs(false)
                    .unwrap();
                c.build().unwrap()
            };

            MtlsEndpoint {
                subscriber,
                sink,
                client_config,
                server_config,
            }
        }

        /// Build an mTLS endpoint with the subscriber on the client side.
        pub(super) fn client_endpoint() -> MtlsEndpoint {
            let sink = VecSink::new();
            let attribution = Attribution {
                service: "test".to_owned(),
                resource: "test".to_owned(),
                component: "test".to_owned(),
            };
            let subscriber = AggregatedMetricsSubscriber::new(sink.clone(), attribution);

            let server_keypair = server_keypair();
            let client_keypair = client_keypair();

            let server_config = {
                let mut c = s2n_tls::config::Builder::new();
                c.set_security_policy(&DEFAULT_TLS13)
                    .unwrap()
                    .load_pem(server_keypair.cert(), server_keypair.key())
                    .unwrap()
                    .trust_pem(client_keypair.ca_cert())
                    .unwrap()
                    .set_client_auth_type(ClientAuthType::Required)
                    .unwrap();
                c.build().unwrap()
            };

            let client_config = {
                let mut c = s2n_tls::config::Builder::new();
                c.set_security_policy(&DEFAULT_TLS13)
                    .unwrap()
                    .load_pem(client_keypair.cert(), client_keypair.key())
                    .unwrap()
                    .trust_pem(server_keypair.ca_cert())
                    .unwrap()
                    .with_system_certs(false)
                    .unwrap()
                    .set_event_subscriber(subscriber.clone())
                    .unwrap();
                c.build().unwrap()
            };

            MtlsEndpoint {
                subscriber,
                sink,
                client_config,
                server_config,
            }
        }

        impl MtlsEndpoint {
            pub fn handshake(&self) {
                let mut pair = TestPair::from_configs(&self.client_config, &self.server_config);
                pair.client.set_server_name("localhost").unwrap();
                pair.handshake().unwrap();
            }
        }
    }

    /// When the subscriber is on the server, `selected_cert` (server's own RSA cert)
    /// should be recorded as server, and `peer_cert_chain` (client's ECDSA cert)
    /// should be recorded as client.
    #[test]
    fn mtls_server_cert_attribution() {
        let endpoint = mtls_helper::server_endpoint();
        endpoint.handshake();
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        let record = &records[0].as_schema().handshake;

        // Sanity check: a cipher was negotiated
        assert_eq!(record.negotiated_ciphers.total(), 1);

        // Server's own cert is RSA 4096 (leaf + 2 chain certs)
        assert_eq!(record.server_leaf_cert_key.get(&CertKeyType::Rsa4096), 1);
        assert_eq!(
            record
                .server_leaf_cert_sig
                .get(&CertSignatureAlgorithm::RsaPkcsSha384),
            1
        );
        assert_eq!(record.server_chain_cert_key.get(&CertKeyType::Rsa4096), 2);
        assert_eq!(
            record
                .server_chain_cert_sig
                .get(&CertSignatureAlgorithm::RsaPkcsSha384),
            2
        );

        // Client's cert is ECDSA P384 (leaf + CA chain cert)
        assert_eq!(record.client_leaf_cert_key.get(&CertKeyType::Secp384r1), 1);
        assert_eq!(
            record
                .client_leaf_cert_sig
                .get(&CertSignatureAlgorithm::EcdsaSha384),
            1
        );
        assert_eq!(record.client_chain_cert_key.get(&CertKeyType::Secp384r1), 1);
        assert_eq!(
            record
                .client_chain_cert_sig
                .get(&CertSignatureAlgorithm::EcdsaSha384),
            1
        );

        // No RSA in client fields, no ECDSA in server fields
        assert_eq!(record.client_leaf_cert_key.get(&CertKeyType::Rsa4096), 0);
        assert_eq!(record.server_leaf_cert_key.get(&CertKeyType::Secp384r1), 0);
    }

    /// When the subscriber is on the client, `selected_cert` (client's own ECDSA cert)
    /// should be recorded as client, and `peer_cert_chain` (server's RSA cert)
    /// should be recorded as server.
    #[test]
    fn mtls_client_cert_attribution() {
        let endpoint = mtls_helper::client_endpoint();
        endpoint.handshake();
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        let record = &records[0].as_schema().handshake;

        // Sanity check: a cipher was negotiated
        assert_eq!(record.negotiated_ciphers.total(), 1);

        // Server's cert (peer) is RSA 4096 (leaf + 2 chain certs)
        assert_eq!(record.server_leaf_cert_key.get(&CertKeyType::Rsa4096), 1);
        assert_eq!(
            record
                .server_leaf_cert_sig
                .get(&CertSignatureAlgorithm::RsaPkcsSha384),
            1
        );
        assert_eq!(record.server_chain_cert_key.get(&CertKeyType::Rsa4096), 2);
        assert_eq!(
            record
                .server_chain_cert_sig
                .get(&CertSignatureAlgorithm::RsaPkcsSha384),
            2
        );

        // Client's own cert is ECDSA P384 (leaf only, selected_cert has no chain)
        assert_eq!(record.client_leaf_cert_key.get(&CertKeyType::Secp384r1), 1);
        assert_eq!(
            record
                .client_leaf_cert_sig
                .get(&CertSignatureAlgorithm::EcdsaSha384),
            1
        );
        assert_eq!(record.client_chain_cert_key.total(), 0);
        assert_eq!(record.client_chain_cert_sig.total(), 0);

        // No RSA in client fields, no ECDSA in server fields
        assert_eq!(record.client_leaf_cert_key.get(&CertKeyType::Rsa4096), 0);
        assert_eq!(record.server_leaf_cert_key.get(&CertKeyType::Secp384r1), 0);
    }

    /// A handshake that fails before the client hello is received should still
    /// record a failure metric without panicking.
    #[test]
    fn failure_without_client_hello() {
        use std::{io::Write, task::Poll};

        let sink = crate::test_utils::VecSink::new();
        let attribution = crate::Attribution {
            service: "test".to_owned(),
            resource: "test".to_owned(),
            component: "test".to_owned(),
        };
        let subscriber = crate::AggregatedMetricsSubscriber::new(sink.clone(), attribution);

        let server_config = {
            let mut config =
                s2n_tls::testing::config_builder(&s2n_tls::security::DEFAULT_TLS13).unwrap();
            config.set_event_subscriber(subscriber.clone()).unwrap();
            config.set_max_blinding_delay(0).unwrap();
            config.build().unwrap()
        };
        let client_config =
            s2n_tls::testing::build_config(&s2n_tls::security::DEFAULT_TLS13).unwrap();

        let mut pair = s2n_tls::testing::TestPair::from_configs(&client_config, &server_config);

        // Write garbage that looks like a TLS record but with invalid content.
        let garbage_record: &[u8] = &[
            0x16, // content_type: handshake
            0x03, 0x01, // version: TLS 1.0
            0x00, 0x05, // length: 5 bytes
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // garbage handshake payload
        ];
        pair.io
            .client_tx_stream
            .borrow_mut()
            .write_all(garbage_record)
            .unwrap();

        // The server should fail because it received garbage instead of a client hello.
        match pair.server.poll_negotiate() {
            Poll::Ready(Err(_)) => {}
            other => panic!("expected server error, got {:?}", other),
        }
        // confirm that the "client hello" was not available
        assert!(pair.server.client_hello().is_err());

        subscriber.finish_record();
        let records = sink.records.lock().unwrap();
        let record = &records[0].as_schema().handshake;

        assert_eq!(record.handshake_failure_count, 1);
        assert_eq!(record.internal_failure, 0);
    }

    /// Make sure that the client issues are properly plumbed in, and show up in
    /// the record. We have to use OpenSSL to get a poorly configured client.
    #[test]
    fn ffdhe_only_client_triggers_tls13_without_s2n_supported_groups() {
        use openssl::ssl::{SslContext, SslMethod};
        use tls_harness::{
            SigType, TlsConnPair,
            cohort::{OpenSslConfig, OpenSslConnection, S2NConfig, S2NConnection},
        };

        let sink = crate::test_utils::VecSink::new();
        let attribution = crate::Attribution {
            service: "test".to_owned(),
            resource: "test".to_owned(),
            component: "test".to_owned(),
        };
        let subscriber = crate::AggregatedMetricsSubscriber::new(sink.clone(), attribution);

        // s2n-tls server: TLS 1.2 only, with subscriber
        let tls12_only_policy = s2n_tls::security::Policy::from_version("20190214").unwrap();
        let server_config: S2NConfig = {
            let mut builder = s2n_tls::config::Builder::new();
            builder.with_system_certs(false).unwrap();
            builder.set_security_policy(&tls12_only_policy).unwrap();
            let cert = tls_harness::harness::read_to_bytes(
                tls_harness::PemType::ServerCertChain,
                SigType::Rsa2048,
            );
            let key = tls_harness::harness::read_to_bytes(
                tls_harness::PemType::ServerKey,
                SigType::Rsa2048,
            );
            builder.load_pem(&cert, &key).unwrap();
            builder.set_event_subscriber(subscriber.clone()).unwrap();
            S2NConfig {
                config: builder.build().unwrap(),
                ticket_storage: Default::default(),
            }
        };

        // OpenSSL client: TLS 1.3 capable, FFDHE-only groups
        let client_config: OpenSslConfig = {
            let mut builder = SslContext::builder(SslMethod::tls_client()).unwrap();
            builder.set_security_level(0);
            builder
                .set_ca_file(tls_harness::get_cert_path(
                    tls_harness::PemType::CACert,
                    SigType::Rsa2048,
                ))
                .unwrap();
            // Only FFDHE groups — s2n-tls doesn't support these for TLS 1.3
            builder.set_groups_list("ffdhe2048").unwrap();
            OpenSslConfig {
                config: builder.build(),
                session_ticket_storage: Default::default(),
            }
        };

        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();

        // Inspect what the server saw in the client hello
        let client_hello = pair.server.connection().client_hello().unwrap();
        let supported_params =
            crate::parsing::ClientHelloSupportedParameters::new(client_hello).unwrap();
        let versions = supported_params.supported_versions();
        let groups = supported_params.supported_groups();
        eprintln!("supported_versions: {:?}", versions);
        eprintln!("supported_groups: {:?}", groups);

        subscriber.finish_record();
        let records = sink.records.lock().unwrap();
        let record = &records[0].as_schema().handshake;

        assert_eq!(record.handshake_success_count, 1);

        let slot = ClientIssue::Tls13WithoutS2NSupportedGroups
            .slot_from_key()
            .unwrap();
        assert_eq!(
            record.client_issues.slots()[slot],
            1,
            "Expected Tls13WithoutS2NSupportedGroups to be incremented"
        );
    }
}
