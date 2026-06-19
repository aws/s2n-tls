// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This test verifies that the most recent released version of
//! s2n-tls-metrics-subscriber (currently 0.0.3) builds and runs against the
//! mainline s2n-tls bindings.
//!
//! If this file fails to compile, it means mainline has broken backward
//! compatibility with the released subscriber. The fix is to restore the
//! missing APIs (with #[deprecated] annotations) in the bindings.

use old_metrics_subscriber::{
    AggregatedMetricsSubscriber, Attribution, MetricRecord, TelemetrySink,
};
use s2n_tls::{
    security::DEFAULT_TLS13,
    testing::{build_config, config_builder, TestPair},
};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct VecSink {
    records: Arc<Mutex<Vec<MetricRecord>>>,
}

impl VecSink {
    fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl TelemetrySink for VecSink {
    fn export_record(&self, record: &MetricRecord) {
        self.records.lock().unwrap().push(record.clone());
    }
}

/// The released s2n-tls-metrics-subscriber 0.0.3 must build and run
/// a handshake against mainline s2n-tls bindings.
#[test]
fn old_event_subscriber_builds() {
    let sink = VecSink::new();
    let attribution = Attribution {
        service: "test-service".to_owned(),
        resource: "test-resource".to_owned(),
        component: "test-component".to_owned(),
    };
    let subscriber = AggregatedMetricsSubscriber::new(sink.clone(), attribution);

    let server_config = {
        let mut cfg = config_builder(&DEFAULT_TLS13).unwrap();
        cfg.set_event_subscriber(subscriber.clone()).unwrap();
        cfg.build().unwrap()
    };
    let client_config = build_config(&DEFAULT_TLS13).unwrap();

    let mut pair = TestPair::from_configs(&client_config, &server_config);
    pair.handshake().unwrap();

    subscriber.finish_record();

    let records = sink.records.lock().unwrap();
    assert_eq!(records.len(), 1);

    // Serialize the record and assert on the content to verify the event APIs
    // populated the subscriber correctly (not just that it compiled).
    let json: serde_json::Value = serde_json::to_value(&records[0]).unwrap();
    let handshake = &json["handshake"];

    // One successful handshake was recorded
    assert_eq!(handshake["handshake_count"], 1);
    assert_eq!(handshake["synthetic_traffic_count"], 0);

    // Negotiated parameters: exactly one of each was counted
    assert_eq!(total_count(&handshake["negotiated_protocols"]), 1);
    assert_eq!(total_count(&handshake["negotiated_ciphers"]), 1);
    assert_eq!(total_count(&handshake["negotiated_groups"]), 1);
    assert_eq!(total_count(&handshake["negotiated_signatures"]), 1);

    // Supported parameters from the client hello should be non-empty
    assert!(total_count(&handshake["supported_protocols"]) >= 1);
    assert!(total_count(&handshake["supported_ciphers"]) >= 1);
    assert!(total_count(&handshake["supported_groups"]) >= 1);
    assert!(total_count(&handshake["supported_signatures"]) >= 1);

    // Timers were populated (non-zero)
    assert!(handshake["handshake_duration_us"].as_u64().unwrap() > 0);
    assert!(handshake["handshake_compute_us"].as_u64().unwrap() > 0);

    // Attribution was passed through
    assert_eq!(json["attribution"]["service"], "test-service");
    assert_eq!(json["attribution"]["resource"], "test-resource");
    assert_eq!(json["attribution"]["component"], "test-component");
}

/// Sum all counts in a frozen counter. The serialized form is an array of
/// `[key, count]` pairs (where key may itself be a nested array).
fn total_count(counter: &serde_json::Value) -> u64 {
    counter
        .as_array()
        .expect("counter should be an array")
        .iter()
        .filter_map(|entry| {
            let arr = entry.as_array()?;
            arr.last()?.as_u64()
        })
        .sum()
}
