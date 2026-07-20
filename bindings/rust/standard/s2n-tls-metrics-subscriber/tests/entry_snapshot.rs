// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Snapshot test that performs a real handshake and renders the resulting
//! MetricRecord as an EMF entry. Any change to what fields the Entry impl
//! emits will show up as a diff in the snapshot file.

use metrique_writer::format::Format;
use metrique_writer_format_emf::Emf;
use s2n_tls::{security::DEFAULT_TLS13, testing::CertKeyPair};
use s2n_tls_metrics_subscriber::{
    AggregatedMetricsSubscriber, Attribution, MetricRecord, TelemetrySink,
};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct CaptureSink(Arc<Mutex<Vec<MetricRecord>>>);
impl TelemetrySink for CaptureSink {
    fn export_record(&self, record: MetricRecord) {
        self.0.lock().unwrap().push(record);
    }
}

/// Normalize non-deterministic values (timestamps, timings) so the snapshot
/// is stable across runs.
fn normalize(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        // Zero out timing fields
        for key in ["handshake_duration_us", "handshake_compute_us"] {
            if obj.contains_key(key) {
                obj.insert(key.to_owned(), serde_json::json!("<DURATION>"));
            }
        }
        // Zero out the EMF timestamp
        if let Some(aws) = obj.get_mut("_aws").and_then(|v| v.as_object_mut()) {
            if aws.contains_key("Timestamp") {
                aws.insert("Timestamp".to_owned(), serde_json::json!("<TIMESTAMP>"));
            }
        }
        // Recurse
        for (_, v) in obj.iter_mut() {
            normalize(v);
        }
    } else if let Some(arr) = value.as_array_mut() {
        for v in arr {
            normalize(v);
        }
    }
}

/// Render a real handshake record to EMF and compare against the expected
/// snapshot.
///
/// If you changed the Entry implementation, update
/// `tests/snapshots/entry_emf.json` to match the new output.
#[test]
fn entry_emf_snapshot() {
    let sink = CaptureSink(Arc::new(Mutex::new(Vec::new())));
    let subscriber = AggregatedMetricsSubscriber::new(
        sink.clone(),
        Attribution {
            service: "my-service".to_owned(),
            resource: "arn:aws:elasticloadbalancing:us-east-1:123:listener/abc".to_owned(),
            component: "test-frontend-whatever".to_owned(),
        },
    );

    let server_config = {
        let keypair = CertKeyPair::from_path(
            "permutations/rsae_pkcs_4096_sha384/",
            "server-chain",
            "server-key",
            "ca-cert",
        );
        let mut c = s2n_tls::config::Builder::new();
        c.set_security_policy(&DEFAULT_TLS13).unwrap();
        c.load_pem(keypair.cert(), keypair.key()).unwrap();
        c.trust_pem(keypair.cert()).unwrap();
        c.set_verify_host_callback(s2n_tls::testing::InsecureAcceptAllCertificatesHandler {})
            .unwrap();
        c.set_event_subscriber(subscriber.clone()).unwrap();
        c.build().unwrap()
    };
    let client_config = {
        let keypair = CertKeyPair::from_path(
            "permutations/rsae_pkcs_4096_sha384/",
            "server-chain",
            "server-key",
            "ca-cert",
        );
        let mut c = s2n_tls::config::Builder::new();
        c.set_security_policy(&DEFAULT_TLS13).unwrap();
        c.load_pem(keypair.cert(), keypair.key()).unwrap();
        c.trust_pem(keypair.cert()).unwrap();
        c.with_system_certs(false).unwrap();
        c.set_verify_host_callback(s2n_tls::testing::InsecureAcceptAllCertificatesHandler {})
            .unwrap();
        c.build().unwrap()
    };
    let mut pair = s2n_tls::testing::TestPair::from_configs(&client_config, &server_config);
    pair.handshake().unwrap();

    // Failed handshake: client does not trust the server cert, shuts down
    // (sending close_notify), and the server receives the alert.
    {
        use std::task::Poll;

        let untrusted_client_config = {
            let mut builder = s2n_tls::config::Builder::new();
            builder.set_security_policy(&DEFAULT_TLS13).unwrap();
            builder.set_max_blinding_delay(0).unwrap();
            builder.with_system_certs(false).unwrap();
            builder.build().unwrap()
        };
        let mut failed_pair =
            s2n_tls::testing::TestPair::from_configs(&untrusted_client_config, &server_config);
        // Drive handshake until client fails cert validation
        assert!(failed_pair.client.poll_negotiate().is_pending());
        assert!(failed_pair.server.poll_negotiate().is_pending());
        let client_err = match failed_pair.client.poll_negotiate() {
            Poll::Ready(Err(e)) => e,
            other => panic!("expected client error, got {:?}", other),
        };
        assert_eq!(client_err.name(), "S2N_ERR_CERT_UNTRUSTED");

        // Client sends close_notify
        assert!(failed_pair.client.poll_shutdown_send().is_ready());

        // Server reads the alert and fails
        let server_err = match failed_pair.server.poll_negotiate() {
            Poll::Ready(Err(e)) => e,
            other => panic!("expected server error, got {:?}", other),
        };
        assert_eq!(server_err.name(), "S2N_ERR_CLOSED");
        assert_eq!(failed_pair.server.alert().unwrap(), 0); // close_notify
    }

    subscriber.finish_record();

    let records = sink.0.lock().unwrap();
    let record = &records[0];

    let mut emf = Emf::no_validations("TlsMetrics".into(), vec![vec![]]);
    let mut buf = Vec::new();
    emf.format(record, &mut buf).unwrap();
    let emf_output = String::from_utf8(buf).unwrap();

    let mut actual: serde_json::Value = serde_json::from_str(&emf_output).unwrap();
    normalize(&mut actual);
    let actual_pretty = serde_json::to_string_pretty(&actual).unwrap();

    // Uncomment to update the snapshot:
    // std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snapshots/entry_emf.json"), &actual_pretty).unwrap();

    let expected = include_str!("snapshots/entry_emf.json").trim_end();
    assert_eq!(actual_pretty, expected);
}
