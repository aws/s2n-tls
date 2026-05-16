// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration test verifying that the subscriber's opaque `MetricRecord` can be
//! serialized and then deserialized into the schema type by a downstream consumer.

/// The opaque `MetricRecord` from the subscriber can be serialized, then
/// deserialized into the schema type by a downstream consumer.
#[test]
fn opaque_serialize_then_schema_deserialize() {
    use s2n_tls_metrics_subscriber::{
        AggregatedMetricsSubscriber, Attribution, MetricRecord, TelemetrySink,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct CaptureSink(Arc<Mutex<Vec<Vec<u8>>>>);
    impl TelemetrySink for CaptureSink {
        fn export_record(&self, record: &MetricRecord) {
            let bytes = serde_json::to_vec(record).unwrap();
            self.0.lock().unwrap().push(bytes);
        }
    }

    let sink = CaptureSink(Arc::new(Mutex::new(Vec::new())));
    let subscriber = AggregatedMetricsSubscriber::new(
        sink.clone(),
        Attribution {
            service: "test".to_owned(),
            resource: "r".to_owned(),
            component: "frontend".to_owned(),
        },
    );

    // Wire up and do a handshake
    use s2n_tls::{
        security::DEFAULT_TLS13,
        testing::{build_config, config_builder},
    };
    let server_config = {
        let mut c = config_builder(&DEFAULT_TLS13).unwrap();
        c.set_event_subscriber(subscriber.clone()).unwrap();
        c.build().unwrap()
    };
    let client_config = build_config(&DEFAULT_TLS13).unwrap();
    let mut pair = s2n_tls::testing::TestPair::from_configs(&client_config, &server_config);
    pair.handshake().unwrap();
    subscriber.finish_record();

    // Consumer deserializes with schema crate
    let captured = sink.0.lock().unwrap();
    assert_eq!(captured.len(), 1);
    let schema_record: s2n_tls_metrics_schema::record::MetricRecord =
        serde_json::from_slice(&captured[0]).unwrap();

    assert_eq!(schema_record.attribution.service, "test");
    assert_eq!(schema_record.attribution.component, "frontend");
    assert_eq!(schema_record.handshake.handshake_count, 1);
    assert!(
        schema_record
            .handshake
            .negotiated_ciphers
            .iter_non_zero()
            .count()
            > 0
    );
}
