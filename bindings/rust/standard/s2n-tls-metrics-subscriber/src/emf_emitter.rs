// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Mutex;

use metrique::writer::Entry;
use metrique_writer::{FormatExt, IoStreamError, format::Format};
use metrique_writer_format_emf::Emf;

use crate::{emf_sink::EmfSink, record::MetricRecord, subscriber::Exporter};

/// The EmfEmitter formats MetricRecords as EMF JSON and writes them through
/// a pluggable [`EmfSink`].
pub struct EmfEmitter<S: EmfSink> {
    sink: S,
    emf_formatter: Mutex<metrique_writer::stream::MergeGlobals<Emf, EmfDimension>>,
}

impl<S: EmfSink> EmfEmitter<S> {
    /// This is the namespace that will show up in the CloudWatch Metrics page.
    const NAMESPACE: &str = "tls/s2n-tls";

    /// * `service_name`: The application name, E.g. CuteKittenService. This will
    ///   be emitted under the "service_name" dimension in your metrics.
    /// * `sink`: The destination for formatted EMF records.
    pub fn new(service_name: String, sink: S) -> Self {
        let emf = Emf::builder(
            Self::NAMESPACE.to_string(),
            vec![vec![EmfDimension::NAME.to_owned()]],
        )
        .build()
        .merge_globals(EmfDimension {
            service_name: service_name.clone(),
        });

        EmfEmitter {
            sink,
            emf_formatter: Mutex::new(emf),
        }
    }
}

impl<S: EmfSink> Exporter for EmfEmitter<S> {
    fn export(&self, metric_record: MetricRecord) {
        let mut buffer = Vec::new();
        let mut formatter = self.emf_formatter.lock().unwrap();

        let write_result = formatter.format(&metric_record, &mut buffer);

        match write_result {
            Ok(_) => {
                if let Err(e) = self.sink.write_record(&buffer) {
                    tracing::error!("failed to write metric to sink: {e}");
                }
            }
            Err(IoStreamError::Validation(v)) => {
                tracing::error!("failed to format metric: {v}");
            }
            Err(IoStreamError::Io(io)) => {
                tracing::error!("IO error formatting metric: {io}");
            }
        }
    }
}

#[derive(Entry)]
struct EmfDimension {
    /// The service name to be used as a `service_name` dimension in CloudWatch.
    service_name: String,
}
impl EmfDimension {
    // this must match the field name of EmfDimension, otherwise the EMF record
    // will fail validation.
    const NAME: &str = "service_name";
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{ARBITRARY_POLICY_1, ARBITRARY_POLICY_2, TestEndpoint};

    /// Verify that finish_record produces non-empty EMF output.
    #[test]
    fn emission() {
        let endpoint = TestEndpoint::new_emf("cute-kitten", &ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        endpoint.subscriber.finish_record();
        let output = endpoint.exporter.take();
        assert!(
            !output.is_empty(),
            "EMF output should not be empty after finish_record"
        );
    }

    /// Snapshot test: verify the EMF output structure matches the expected sample.
    ///
    /// This test normalizes dynamic fields (timestamp, durations) so the comparison
    /// is stable across runs.
    #[test]
    fn snapshot() {
        let endpoint = TestEndpoint::new_emf("cute-kitten", &ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_2);

        endpoint.subscriber.finish_record();
        let output = endpoint.exporter.take();
        let output_str = String::from_utf8(output).unwrap();

        let mut actual: serde_json::Value = serde_json::from_str(&output_str).unwrap();

        let expected_str = include_str!("../resources/emf_sample.json");
        let mut expected: serde_json::Value = serde_json::from_str(expected_str).unwrap();

        // Normalize dynamic fields so the snapshot is stable.
        for val in [&mut actual, &mut expected] {
            val["_aws"]["Timestamp"] = serde_json::json!(0);
            val["handshake_duration_us"] = serde_json::json!(0);
            val["handshake_compute_us"] = serde_json::json!(0);
        }

        assert_eq!(actual, expected);
    }

    /// Verify that the EMF output contains expected fields and values.
    #[test]
    fn record_contents() {
        let endpoint = TestEndpoint::new_emf("cute-kitten", &ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        endpoint.subscriber.finish_record();
        let output = endpoint.exporter.take();
        let output_str = String::from_utf8(output).unwrap();

        let json: serde_json::Value = serde_json::from_str(&output_str).unwrap();

        // Verify structural fields
        assert!(json["_aws"]["CloudWatchMetrics"].is_array());
        assert_eq!(json["service_name"], "test_server");
        assert_eq!(json["resource"], "cute-kitten");
        assert_eq!(json["handshake_count"], 1);

        // Duration fields should be present and non-negative
        assert!(json["handshake_duration_us"].as_u64().unwrap() > 0);
        assert!(json["handshake_compute_us"].as_u64().unwrap() > 0);
    }

    /// Verify that multiple finish_record calls accumulate separate records in the buffer.
    #[test]
    fn buffer() {
        let endpoint = TestEndpoint::new_emf("cute-kitten", &ARBITRARY_POLICY_1);

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();

        let output = endpoint.exporter.take();
        let output_str = String::from_utf8(output).unwrap();

        // The TestBuffer doesn't add newlines between records (unlike WriterSink),
        // but each JSON record starts with '{'. Count the top-level JSON objects.
        // We can parse by finding balanced braces or just check we have two records.
        let record_count = output_str.matches("\"_aws\"").count();
        assert_eq!(record_count, 2, "Expected two EMF records in the buffer");
    }
}
