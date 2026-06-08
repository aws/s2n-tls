// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the public API surface of s2n-tls-metrics-schema.
//!
//! These tests exercise deserialization of `MetricRecord`, field access,
//! counter slot layout, and round-trip serialization.

use std::time::SystemTime;

use s2n_tls_metrics_schema::static_lists::{
    CIPHER_COUNT, Cipher, FiniteCounter, GROUP_COUNT, Group, PROTOCOL_COUNT, SIGNATURE_COUNT,
    Signature, Version,
};

fn sample_schema_record() -> s2n_tls_metrics_schema::record::MetricRecord {
    let json = serde_json::json!({
        "attribution": {
            "service": "my-service",
            "resource": "arn:aws:elasticloadbalancing:us-east-1:123:listener/abc"
        },
        "handshake": {
            "freeze_time": {"secs_since_epoch": 1_700_000_000u64, "nanos_since_epoch": 0u32},
            "handshake_success_count": 1000,
            "negotiated_protocols": [[0x0303u16, 400], [0x0304u16, 600]],
            "negotiated_ciphers": [[[0x13, 0x01], 600], [[0x13, 0x02], 400]],
            "negotiated_groups": [[23u16, 500], [29u16, 500]],
            "negotiated_signatures": [[2052u16, 1000]],
            "sslv2_client_hello": 2,
            "supported_protocols": [[0x0303u16, 1000], [0x0304u16, 1000]],
            "supported_ciphers": [[[0x13, 0x01], 1000], [[0x13, 0x02], 1000]],
            "supported_groups": [[23u16, 1000], [29u16, 1000]],
            "supported_signatures": [[2052u16, 1000]],
            "compatibility_general20251201": 950,
            "compatibility_fips20251201": 800,
            "compatibility_cnsa1": 100,
            "compatibility_cnsa2": 0,
            "handshake_duration_us": 50000,
            "handshake_compute_us": 25000
        }
    });
    serde_json::from_value(json).unwrap()
}

/// Verify CBOR stream round-trip: serialize via schema, deserialize back.
#[test]
fn cbor_stream_round_trip() {
    let original = sample_schema_record();

    let mut stream = Vec::new();
    for _ in 0..3 {
        ciborium::into_writer(&original, &mut stream).unwrap();
    }

    let mut cursor = std::io::Cursor::new(&stream);
    let mut records: Vec<s2n_tls_metrics_schema::record::MetricRecord> = Vec::new();
    loop {
        match ciborium::from_reader(&mut cursor) {
            Ok(record) => records.push(record),
            Err(ciborium::de::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => panic!("deserialization error: {e}"),
        }
    }

    assert_eq!(records.len(), 3);
    for r in &records {
        assert_eq!(r.attribution.service, "my-service");
        assert_eq!(r.handshake.handshake_success_count, 1000);
    }
}

/// Schema field access after deserialization.
#[test]
fn schema_field_access() {
    let record = sample_schema_record();

    assert_eq!(record.attribution.service, "my-service");
    assert_eq!(
        record.attribution.resource,
        "arn:aws:elasticloadbalancing:us-east-1:123:listener/abc"
    );

    assert_eq!(record.handshake.handshake_success_count, 1000);
    assert_eq!(record.handshake.sslv2_client_hello, 2);
    assert_eq!(record.handshake.compatibility_general20251201, 950);
    assert_eq!(record.handshake.compatibility_fips20251201, 800);
    assert_eq!(record.handshake.compatibility_cnsa1, 100);
    assert_eq!(record.handshake.compatibility_cnsa2, 0);
    assert_eq!(record.handshake.handshake_duration_us, 50000);
    assert_eq!(record.handshake.handshake_compute_us, 25000);

    let dur = record
        .handshake
        .freeze_time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    assert_eq!(dur.as_secs(), 1_700_000_000);
}

#[test]
fn frozen_counter_slots_dense_array() {
    let record = sample_schema_record();

    let protocol_slots = record.handshake.negotiated_protocols.slots();
    assert_eq!(protocol_slots.len(), PROTOCOL_COUNT);
    assert_eq!(protocol_slots.iter().sum::<u64>(), 1000);

    let cipher_slots = record.handshake.negotiated_ciphers.slots();
    assert_eq!(cipher_slots.len(), CIPHER_COUNT);
    assert_eq!(cipher_slots.iter().sum::<u64>(), 1000);

    let group_slots = record.handshake.negotiated_groups.slots();
    assert_eq!(group_slots.len(), GROUP_COUNT);
    assert_eq!(group_slots.iter().sum::<u64>(), 1000);

    let sig_slots = record.handshake.negotiated_signatures.slots();
    assert_eq!(sig_slots.len(), SIGNATURE_COUNT);
    assert_eq!(sig_slots.iter().sum::<u64>(), 1000);
}

#[test]
fn key_from_slot_produces_display_names() {
    for slot in 0..PROTOCOL_COUNT {
        let name = Version::key_from_slot(slot).unwrap().to_string();
        assert!(!name.is_empty());
        assert!(!name.starts_with("unknown"));
    }

    for slot in 0..CIPHER_COUNT {
        let name = Cipher::key_from_slot(slot).unwrap().to_string();
        assert!(!name.is_empty());
        assert!(!name.starts_with("unknown"));
    }

    for slot in 0..GROUP_COUNT {
        let name = Group::key_from_slot(slot).unwrap().to_string();
        assert!(!name.is_empty());
        assert!(!name.starts_with("unknown"));
    }

    for slot in 0..SIGNATURE_COUNT {
        let name = Signature::key_from_slot(slot).unwrap().to_string();
        assert!(!name.is_empty());
        assert!(!name.starts_with("unknown"));
    }
}

#[test]
fn iter_non_zero_yields_expected_triples() {
    let record = sample_schema_record();

    let non_zero: Vec<(usize, Version, u64)> = record
        .handshake
        .negotiated_protocols
        .iter_non_zero()
        .collect();
    assert_eq!(non_zero.len(), 2);

    let total: u64 = non_zero.iter().map(|(_, _, c)| c).sum();
    assert_eq!(total, 1000);

    for (slot, element, count) in &non_zero {
        assert!(count > &0);
        let name = element.to_string();
        assert!(
            name == "TLSv1_2" || name == "TLSv1_3",
            "unexpected protocol: {name}"
        );
        assert_eq!(Version::key_from_slot(*slot).unwrap(), *element);
    }
}

#[test]
fn slots_and_iter_non_zero_are_consistent() {
    let record = sample_schema_record();

    let slots = record.handshake.negotiated_ciphers.slots();
    let from_iter: Vec<(usize, u64)> = record
        .handshake
        .negotiated_ciphers
        .iter_non_zero()
        .map(|(slot, _, count)| (slot, count))
        .collect();

    for &(slot, count) in &from_iter {
        assert_eq!(slots[slot], count);
    }

    let non_zero_from_slots: Vec<(usize, u64)> = slots
        .iter()
        .enumerate()
        .filter(|&(_, c)| *c > 0)
        .map(|(i, &c)| (i, c))
        .collect();
    assert_eq!(from_iter, non_zero_from_slots);
}

#[test]
fn cbor_round_trip_preserves_all_fields() {
    let original = sample_schema_record();
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&original, &mut cbor_bytes).unwrap();
    let recovered: s2n_tls_metrics_schema::record::MetricRecord =
        ciborium::from_reader(cbor_bytes.as_slice()).unwrap();

    assert_eq!(original, recovered);
}

#[test]
fn empty_record_has_zero_slots() {
    let json = serde_json::json!({
        "attribution": { "service": "s", "resource": "r" },
        "handshake": {
            "freeze_time": {"secs_since_epoch": 0u64, "nanos_since_epoch": 0u32},
            "handshake_success_count": 0u64
        }
    });
    let record: s2n_tls_metrics_schema::record::MetricRecord =
        serde_json::from_value(json).unwrap();

    assert!(
        record
            .handshake
            .negotiated_protocols
            .slots()
            .iter()
            .all(|&c| c == 0)
    );
    assert!(
        record
            .handshake
            .negotiated_ciphers
            .slots()
            .iter()
            .all(|&c| c == 0)
    );
    assert!(
        record
            .handshake
            .negotiated_groups
            .slots()
            .iter()
            .all(|&c| c == 0)
    );
    assert!(
        record
            .handshake
            .negotiated_signatures
            .slots()
            .iter()
            .all(|&c| c == 0)
    );
    assert!(
        record
            .handshake
            .supported_protocols
            .slots()
            .iter()
            .all(|&c| c == 0)
    );
    assert!(
        record
            .handshake
            .supported_ciphers
            .slots()
            .iter()
            .all(|&c| c == 0)
    );
    assert!(
        record
            .handshake
            .supported_groups
            .slots()
            .iter()
            .all(|&c| c == 0)
    );
    assert!(
        record
            .handshake
            .supported_signatures
            .slots()
            .iter()
            .all(|&c| c == 0)
    );

    assert_eq!(
        record
            .handshake
            .negotiated_protocols
            .iter_non_zero()
            .count(),
        0
    );
}
