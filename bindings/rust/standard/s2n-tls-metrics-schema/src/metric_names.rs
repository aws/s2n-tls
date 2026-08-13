// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canonical metric name definitions and caching for TLS telemetry.
//!
//! All serialized metric names representations are defined here.
//! Downstream crates should import from this module rather than
//! duplicating string literals.

use std::{
    collections::HashMap,
    fmt::Display,
    sync::{LazyLock, RwLock},
};

use crate::static_lists::{
    Alert, CERT_KEY_COUNT, CERT_SIG_COUNT, CIPHER_COUNT, CertKeyType, CertSignatureAlgorithm,
    Cipher, ClientIssue, DEFINED_ALERTS_COUNT, FiniteCounter, GROUP_COUNT, Group, PROTOCOL_COUNT,
    SIGNATURE_COUNT, Signature, Version,
};

/// Cache key keyed by slot index so the cache type stays non-generic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TelemetryLabel {
    prefix: &'static str,
    counter_slot: usize,
}

/// We want all of our metrics counters to be prefixed, e.g. `group.negotiated.secp256r1`
/// This will allow much easier CloudWatch graphs, because you can say things like
/// "graph all `group.negotiated.*` metrics"
///
/// metrique needs the string to be static, so we deliberately "leak" the data.
///
/// This is acceptable because it's just a finite set of values.
#[derive(Debug, Default)]
struct TelemetryLabeller(RwLock<HashMap<TelemetryLabel, &'static str>>);

impl TelemetryLabeller {
    fn get(&self, telemetry: &TelemetryLabel) -> Option<&'static str> {
        self.0.read().unwrap().get(telemetry).map(|label| &**label)
    }

    fn insert(&self, telemetry: &TelemetryLabel, value: String) -> &'static str {
        let mut write_lock = self.0.write().unwrap();
        // it's important that we only leak _after_ we have acquired the write lock.
        // otherwise we might end up leaking extra copies of the metric label
        let label = value.leak();
        write_lock.insert(*telemetry, label);
        label
    }
}

/// lookup from metric to the prefixed string, e.g. "group.negotiated.secp256r1"
pub fn telemetry_label<T>(counter_slot: usize, item: T, prefix: &'static str) -> &'static str
where
    T: Display,
{
    static PREFIXER: LazyLock<TelemetryLabeller> = LazyLock::new(TelemetryLabeller::default);

    let key = TelemetryLabel {
        prefix,
        counter_slot,
    };

    match PREFIXER.get(&key) {
        Some(label) => label,
        None => PREFIXER.insert(&key, format!("{prefix}.{item}")),
    }
}

pub const HANDSHAKE_SUCCESS_COUNT: &str = "handshake_success_count";
pub const HANDSHAKE_FAILURE_COUNT: &str = "handshake_failure_count";
pub const COMPATIBILITY_GENERAL20251201: &str = "compatibility.general20251201";
pub const COMPATIBILITY_FIPS20251201: &str = "compatibility.fips20251201";
pub const COMPATIBILITY_CNSA1: &str = "compatibility.cnsa1";
pub const COMPATIBILITY_CNSA2: &str = "compatibility.cnsa2";
pub const SECURITY_POLICY_PREFIX: &str = "tls_policy";
pub const SECURITY_POLICY_TOO_MANY: &str = "tls_policy.TOO_MANY";

pub fn security_policy_name(policy: &str) -> String {
    format!("{SECURITY_POLICY_PREFIX}.{policy}")
}

pub const SSLV2_CLIENT_HELLO: &str = "sslv2_client_hello";
pub const HANDSHAKE_DURATION_US: &str = "handshake_duration_us";
pub const HANDSHAKE_COMPUTE_US: &str = "handshake_compute_us";
pub const SYNTHETIC_TRAFFIC_COUNT: &str = "synthetic_traffic_count";
pub const INTERNAL_FAILURE: &str = "internal_failure";

pub const ALL_SCALARS: &[&str] = &[
    COMPATIBILITY_GENERAL20251201,
    COMPATIBILITY_FIPS20251201,
    COMPATIBILITY_CNSA1,
    COMPATIBILITY_CNSA2,
    SSLV2_CLIENT_HELLO,
    HANDSHAKE_SUCCESS_COUNT,
    HANDSHAKE_FAILURE_COUNT,
    HANDSHAKE_DURATION_US,
    HANDSHAKE_COMPUTE_US,
    SYNTHETIC_TRAFFIC_COUNT,
    SERVER_CERT_PARSE_FAILURE,
    CLIENT_CERT_PARSE_FAILURE,
    INTERNAL_FAILURE,
];

/// A counter group descriptor: prefix string, element count, and cached name accessor.
///
/// Each group represents one (TlsParam, State) combination, e.g. "cipher.negotiated".
/// Individual metric names are formed as `"{prefix}.{element}"` and cached via
/// [`telemetry_label`] for zero-allocation access after the first call.
pub struct CounterGroup {
    pub prefix: &'static str,
    pub count: usize,
    name_from_slot: fn(usize, &'static str) -> &'static str,
}

impl CounterGroup {
    /// Returns the cached metric name for a slot index.
    pub fn metric_name(&self, slot: usize) -> &'static str {
        debug_assert!(
            slot < self.count,
            "slot {slot} out of range for {}",
            self.prefix
        );
        (self.name_from_slot)(slot, self.prefix)
    }

    /// Returns the cached metric name when the caller already has the element.
    pub fn metric_name_for<T: Display>(&self, slot: usize, element: T) -> &'static str {
        telemetry_label(slot, element, self.prefix)
    }
}

fn version_metric_name(slot: usize, prefix: &'static str) -> &'static str {
    telemetry_label(slot, Version::key_from_slot(slot).unwrap(), prefix)
}

fn cipher_metric_name(slot: usize, prefix: &'static str) -> &'static str {
    telemetry_label(slot, Cipher::key_from_slot(slot).unwrap(), prefix)
}

fn group_metric_name(slot: usize, prefix: &'static str) -> &'static str {
    telemetry_label(slot, Group::key_from_slot(slot).unwrap(), prefix)
}

fn signature_metric_name(slot: usize, prefix: &'static str) -> &'static str {
    telemetry_label(slot, Signature::key_from_slot(slot).unwrap(), prefix)
}

fn alert_metric_name(slot: usize, prefix: &'static str) -> &'static str {
    telemetry_label(slot, Alert::key_from_slot(slot).unwrap(), prefix)
}

fn client_issue_metric_name(slot: usize, prefix: &'static str) -> &'static str {
    telemetry_label(slot, ClientIssue::key_from_slot(slot).unwrap(), prefix)
}

pub const ALERTS: CounterGroup = CounterGroup {
    prefix: "alert",
    count: DEFINED_ALERTS_COUNT,
    name_from_slot: alert_metric_name,
};

pub const CLIENT_ISSUES: CounterGroup = CounterGroup {
    prefix: "client_issue",
    count: ClientIssue::COUNT,
    name_from_slot: client_issue_metric_name,
};

fn cert_key_metric_name(slot: usize, prefix: &'static str) -> &'static str {
    telemetry_label(slot, CertKeyType::key_from_slot(slot).unwrap(), prefix)
}

fn cert_sig_metric_name(slot: usize, prefix: &'static str) -> &'static str {
    telemetry_label(
        slot,
        CertSignatureAlgorithm::key_from_slot(slot).unwrap(),
        prefix,
    )
}

pub const SERVER_CERT_PARSE_FAILURE: &str = "cert.server.subscriber_parse_failure";
pub const CLIENT_CERT_PARSE_FAILURE: &str = "cert.client.subscriber_parse_failure";

pub mod cert {
    use super::*;

    pub const SERVER_LEAF_KEY: CounterGroup = CounterGroup {
        prefix: "cert.server.leaf.key",
        count: CERT_KEY_COUNT,
        name_from_slot: cert_key_metric_name,
    };
    pub const SERVER_LEAF_SIG: CounterGroup = CounterGroup {
        prefix: "cert.server.leaf.sig",
        count: CERT_SIG_COUNT,
        name_from_slot: cert_sig_metric_name,
    };
    pub const SERVER_CHAIN_KEY: CounterGroup = CounterGroup {
        prefix: "cert.server.chain.key",
        count: CERT_KEY_COUNT,
        name_from_slot: cert_key_metric_name,
    };
    pub const SERVER_CHAIN_SIG: CounterGroup = CounterGroup {
        prefix: "cert.server.chain.sig",
        count: CERT_SIG_COUNT,
        name_from_slot: cert_sig_metric_name,
    };
    pub const CLIENT_LEAF_KEY: CounterGroup = CounterGroup {
        prefix: "cert.client.leaf.key",
        count: CERT_KEY_COUNT,
        name_from_slot: cert_key_metric_name,
    };
    pub const CLIENT_LEAF_SIG: CounterGroup = CounterGroup {
        prefix: "cert.client.leaf.sig",
        count: CERT_SIG_COUNT,
        name_from_slot: cert_sig_metric_name,
    };
    pub const CLIENT_CHAIN_KEY: CounterGroup = CounterGroup {
        prefix: "cert.client.chain.key",
        count: CERT_KEY_COUNT,
        name_from_slot: cert_key_metric_name,
    };
    pub const CLIENT_CHAIN_SIG: CounterGroup = CounterGroup {
        prefix: "cert.client.chain.sig",
        count: CERT_SIG_COUNT,
        name_from_slot: cert_sig_metric_name,
    };
}

macro_rules! define_counter_groups {
    ($mod_name:ident, $state:literal) => {
        pub mod $mod_name {
            use super::*;

            pub const VERSIONS: CounterGroup = CounterGroup {
                prefix: concat!("version.", $state),
                count: PROTOCOL_COUNT,
                name_from_slot: version_metric_name,
            };

            pub const CIPHERS: CounterGroup = CounterGroup {
                prefix: concat!("cipher.", $state),
                count: CIPHER_COUNT,
                name_from_slot: cipher_metric_name,
            };

            pub const GROUPS: CounterGroup = CounterGroup {
                prefix: concat!("group.", $state),
                count: GROUP_COUNT,
                name_from_slot: group_metric_name,
            };

            pub const SIGNATURES: CounterGroup = CounterGroup {
                prefix: concat!("signature_scheme.", $state),
                count: SIGNATURE_COUNT,
                name_from_slot: signature_metric_name,
            };

            pub const ALL: &[&CounterGroup] = &[&VERSIONS, &CIPHERS, &GROUPS, &SIGNATURES];
        }
    };
}

define_counter_groups!(negotiated, "negotiated");
define_counter_groups!(supported, "supported");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_output() {
        assert_eq!(
            telemetry_label(0, Cipher::TLS_AES_256_GCM_SHA384, "cipher.negotiated"),
            "cipher.negotiated.TLS_AES_256_GCM_SHA384"
        );
    }
}
