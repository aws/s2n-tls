// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::{
    attribution::Attribution,
    bounded_set::FrozenBoundedStringSet,
    counter::FrozenCounter,
    static_lists::{
        Alert, CERT_KEY_COUNT, CERT_SIG_COUNT, CIPHER_COUNT, CertKeyType, CertSignatureAlgorithm,
        Cipher, DEFINED_ALERTS_COUNT, GROUP_COUNT, Group, PROTOCOL_COUNT, SIGNATURE_COUNT,
        Signature, Version,
    },
};

use crate::{
    metric_names::{self as names, CounterGroup, negotiated, supported},
    static_lists::FiniteCounter,
};

/// Metric Record is an type which implements `metrique_writer::Entry`
/// (when the `metrique` feature is enabled).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricRecord {
    pub attribution: Attribution,
    pub handshake: FrozenHandshakeRecord,
}

impl metrique_writer::Entry for MetricRecord {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        let operation = if self.attribution.component.is_empty() {
            "TlsTelemetry".to_owned()
        } else {
            format!("TlsTelemetry.{}", self.attribution.component)
        };
        writer.value("Operation", &operation);
        writer.value("service", &self.attribution.service);
        writer.value("resource", &self.attribution.resource);
        self.handshake.write(writer)
    }
}

/// `SystemTime` has no meaningful `Default` impl for serde's purposes, so we
/// pick `UNIX_EPOCH` explicitly as the `#[serde(default = ...)]` target for
/// `freeze_time`.
fn system_time_epoch() -> SystemTime {
    SystemTime::UNIX_EPOCH
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrozenHandshakeRecord {
    #[serde(default = "system_time_epoch")]
    pub freeze_time: SystemTime,

    #[serde(default)]
    pub security_policies: FrozenBoundedStringSet,

    #[serde(default)]
    pub handshake_success_count: u64,

    #[serde(default)]
    pub handshake_failure_count: u64,

    #[serde(default)]
    pub alerts: FrozenCounter<DEFINED_ALERTS_COUNT, Alert>,

    #[serde(default)]
    pub negotiated_protocols: FrozenCounter<PROTOCOL_COUNT, Version>,
    #[serde(default)]
    pub negotiated_ciphers: FrozenCounter<CIPHER_COUNT, Cipher>,
    #[serde(default)]
    pub negotiated_groups: FrozenCounter<GROUP_COUNT, Group>,
    #[serde(default)]
    pub negotiated_signatures: FrozenCounter<SIGNATURE_COUNT, Signature>,

    #[serde(default)]
    pub sslv2_client_hello: u64,
    #[serde(default)]
    pub supported_protocols: FrozenCounter<PROTOCOL_COUNT, Version>,
    #[serde(default)]
    pub supported_ciphers: FrozenCounter<CIPHER_COUNT, Cipher>,
    #[serde(default)]
    pub supported_groups: FrozenCounter<GROUP_COUNT, Group>,
    #[serde(default)]
    pub supported_signatures: FrozenCounter<SIGNATURE_COUNT, Signature>,

    #[serde(default)]
    pub server_leaf_cert_key: FrozenCounter<CERT_KEY_COUNT, CertKeyType>,
    #[serde(default)]
    pub server_leaf_cert_sig: FrozenCounter<CERT_SIG_COUNT, CertSignatureAlgorithm>,
    #[serde(default)]
    pub server_chain_cert_key: FrozenCounter<CERT_KEY_COUNT, CertKeyType>,
    #[serde(default)]
    pub server_chain_cert_sig: FrozenCounter<CERT_SIG_COUNT, CertSignatureAlgorithm>,
    #[serde(default)]
    pub client_leaf_cert_key: FrozenCounter<CERT_KEY_COUNT, CertKeyType>,
    #[serde(default)]
    pub client_leaf_cert_sig: FrozenCounter<CERT_SIG_COUNT, CertSignatureAlgorithm>,
    #[serde(default)]
    pub client_chain_cert_key: FrozenCounter<CERT_KEY_COUNT, CertKeyType>,
    #[serde(default)]
    pub client_chain_cert_sig: FrozenCounter<CERT_SIG_COUNT, CertSignatureAlgorithm>,
    #[serde(default)]
    pub server_cert_parsing_failure: u64,
    #[serde(default)]
    pub client_cert_parsing_failure: u64,

    #[serde(default)]
    pub compatibility_general20251201: u64,
    #[serde(default)]
    pub compatibility_fips20251201: u64,
    #[serde(default)]
    pub compatibility_cnsa1: u64,
    #[serde(default)]
    pub compatibility_cnsa2: u64,

    #[serde(default)]
    pub handshake_duration_us: u64,
    #[serde(default)]
    pub handshake_compute_us: u64,

    #[serde(default)]
    pub synthetic_traffic_count: u64,

    /// Number of handshakes where an internal error prevented the metrics
    /// subscriber from fully recording metrics.
    #[serde(default)]
    pub internal_failure: u64,
}

impl Default for FrozenHandshakeRecord {
    fn default() -> Self {
        Self {
            freeze_time: SystemTime::UNIX_EPOCH,
            handshake_success_count: 0,
            handshake_failure_count: 0,
            alerts: FrozenCounter::default(),
            negotiated_protocols: FrozenCounter::default(),
            negotiated_ciphers: FrozenCounter::default(),
            negotiated_groups: FrozenCounter::default(),
            negotiated_signatures: FrozenCounter::default(),
            sslv2_client_hello: 0,
            supported_protocols: FrozenCounter::default(),
            supported_ciphers: FrozenCounter::default(),
            supported_groups: FrozenCounter::default(),
            supported_signatures: FrozenCounter::default(),
            server_leaf_cert_key: FrozenCounter::default(),
            server_leaf_cert_sig: FrozenCounter::default(),
            server_chain_cert_key: FrozenCounter::default(),
            server_chain_cert_sig: FrozenCounter::default(),
            client_leaf_cert_key: FrozenCounter::default(),
            client_leaf_cert_sig: FrozenCounter::default(),
            client_chain_cert_key: FrozenCounter::default(),
            client_chain_cert_sig: FrozenCounter::default(),
            server_cert_parsing_failure: 0,
            client_cert_parsing_failure: 0,
            compatibility_general20251201: 0,
            compatibility_fips20251201: 0,
            compatibility_cnsa1: 0,
            compatibility_cnsa2: 0,
            handshake_duration_us: 0,
            handshake_compute_us: 0,
            synthetic_traffic_count: 0,
            internal_failure: 0,
            security_policies: Default::default(),
        }
    }
}

impl metrique_writer::Entry for FrozenHandshakeRecord {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        match &self.security_policies {
            FrozenBoundedStringSet::TooMany => {
                writer.value(names::SECURITY_POLICY_TOO_MANY, &1_u64)
            }
            FrozenBoundedStringSet::Entries(hash_set) => {
                for policy in hash_set {
                    writer.value(names::security_policy_name(policy), &1_u64);
                }
            }
        }
        writer.timestamp(self.freeze_time);

        fn write_counter<'a, const N: usize, T, W>(
            counter: &'a FrozenCounter<N, T>,
            group: &CounterGroup,
            writer: &mut W,
        ) where
            T: FiniteCounter<N> + std::fmt::Display,
            W: metrique_writer::EntryWriter<'a>,
        {
            for (slot, element, count) in counter.iter_non_zero() {
                writer.value(group.metric_name_for(slot, element), &count);
            }
        }

        write_counter(&self.negotiated_protocols, &negotiated::VERSIONS, writer);
        write_counter(&self.negotiated_ciphers, &negotiated::CIPHERS, writer);
        write_counter(&self.negotiated_groups, &negotiated::GROUPS, writer);
        write_counter(&self.negotiated_signatures, &negotiated::SIGNATURES, writer);
        write_counter(&self.supported_protocols, &supported::VERSIONS, writer);
        write_counter(&self.supported_ciphers, &supported::CIPHERS, writer);
        write_counter(&self.supported_groups, &supported::GROUPS, writer);
        write_counter(&self.supported_signatures, &supported::SIGNATURES, writer);
        write_counter(
            &self.server_leaf_cert_key,
            &names::cert::SERVER_LEAF_KEY,
            writer,
        );
        write_counter(
            &self.server_leaf_cert_sig,
            &names::cert::SERVER_LEAF_SIG,
            writer,
        );
        write_counter(
            &self.server_chain_cert_key,
            &names::cert::SERVER_CHAIN_KEY,
            writer,
        );
        write_counter(
            &self.server_chain_cert_sig,
            &names::cert::SERVER_CHAIN_SIG,
            writer,
        );
        write_counter(
            &self.client_leaf_cert_key,
            &names::cert::CLIENT_LEAF_KEY,
            writer,
        );
        write_counter(
            &self.client_leaf_cert_sig,
            &names::cert::CLIENT_LEAF_SIG,
            writer,
        );
        write_counter(
            &self.client_chain_cert_key,
            &names::cert::CLIENT_CHAIN_KEY,
            writer,
        );
        write_counter(
            &self.client_chain_cert_sig,
            &names::cert::CLIENT_CHAIN_SIG,
            writer,
        );
        writer.value(
            names::SERVER_CERT_PARSE_FAILURE,
            &self.server_cert_parsing_failure,
        );
        writer.value(
            names::CLIENT_CERT_PARSE_FAILURE,
            &self.client_cert_parsing_failure,
        );

        writer.value(
            names::COMPATIBILITY_GENERAL20251201,
            &self.compatibility_general20251201,
        );
        writer.value(
            names::COMPATIBILITY_FIPS20251201,
            &self.compatibility_fips20251201,
        );
        writer.value(names::COMPATIBILITY_CNSA1, &self.compatibility_cnsa1);
        writer.value(names::COMPATIBILITY_CNSA2, &self.compatibility_cnsa2);

        writer.value(names::SSLV2_CLIENT_HELLO, &self.sslv2_client_hello);
        writer.value(
            names::HANDSHAKE_SUCCESS_COUNT,
            &self.handshake_success_count,
        );
        writer.value(
            names::HANDSHAKE_FAILURE_COUNT,
            &self.handshake_failure_count,
        );
        write_counter(&self.alerts, &names::ALERTS, writer);
        writer.value(names::HANDSHAKE_DURATION_US, &self.handshake_duration_us);
        writer.value(names::HANDSHAKE_COMPUTE_US, &self.handshake_compute_us);
        writer.value(
            names::SYNTHETIC_TRAFFIC_COUNT,
            &self.synthetic_traffic_count,
        );
        writer.value(
            names::INTERNAL_FAILURE,
            &self.internal_failure,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_missing_fields_uses_defaults() {
        let json = r#"{"handshake_success_count": 10}"#;
        let record: FrozenHandshakeRecord = serde_json::from_str(json).unwrap();

        assert_eq!(record.handshake_success_count, 10);
        assert_eq!(record.freeze_time, SystemTime::UNIX_EPOCH);

        assert_eq!(record.negotiated_protocols, FrozenCounter::default());
        assert_eq!(record.negotiated_ciphers, FrozenCounter::default());
        assert_eq!(record.negotiated_groups, FrozenCounter::default());
        assert_eq!(record.negotiated_signatures, FrozenCounter::default());
        assert_eq!(record.alerts, FrozenCounter::default());
        assert_eq!(record.supported_protocols, FrozenCounter::default());
        assert_eq!(record.supported_ciphers, FrozenCounter::default());
        assert_eq!(record.supported_groups, FrozenCounter::default());
        assert_eq!(record.supported_signatures, FrozenCounter::default());

        assert_eq!(record.sslv2_client_hello, 0);
        assert_eq!(record.compatibility_general20251201, 0);
        assert_eq!(record.compatibility_fips20251201, 0);
        assert_eq!(record.compatibility_cnsa1, 0);
        assert_eq!(record.compatibility_cnsa2, 0);
        assert_eq!(record.handshake_duration_us, 0);
        assert_eq!(record.handshake_compute_us, 0);
        assert_eq!(record.synthetic_traffic_count, 0);
    }
}
