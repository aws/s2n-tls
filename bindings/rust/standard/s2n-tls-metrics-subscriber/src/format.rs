// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::record::MetricRecord;
use metrique_writer::format::Format;
use std::fmt;

/// Determines how a [`MetricRecord`] is serialized before being written to a Sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationFormat {
    /// Querylog JSON format via `metrique_writer::Entry` and the JSON formatter.
    ///
    /// Produces human-readable JSON with named metric keys like
    /// `"cipher.negotiated.TLS_AES_128_GCM_SHA256": 3`.
    Querylog,
    /// CBOR binary format (via `ciborium` / serde `Serialize`).
    Cbor,
}

impl SerializationFormat {
    /// Serialize a `MetricRecord` into bytes using this format.
    pub(crate) fn serialize(&self, record: &MetricRecord) -> Result<Vec<u8>, SerializationError> {
        match self {
            SerializationFormat::Querylog => {
                let mut json_fmt = metrique_writer_format_json::Json::new();
                let mut buf = Vec::new();
                json_fmt.format(record, &mut buf).map_err(|e| match e {
                    metrique_writer::IoStreamError::Io(io) => SerializationError::Io(io),
                    metrique_writer::IoStreamError::Validation(v) => SerializationError::Io(
                        std::io::Error::new(std::io::ErrorKind::InvalidData, v),
                    ),
                })?;
                Ok(buf)
            }
            SerializationFormat::Cbor => {
                let mut buf = Vec::new();
                ciborium::ser::into_writer(record, &mut buf).map_err(SerializationError::Cbor)?;
                Ok(buf)
            }
        }
    }
}

/// Errors that can occur during metric record serialization.
#[derive(Debug)]
pub enum SerializationError {
    /// IO or querylog formatting error
    Io(std::io::Error),
    /// CBOR serialization error
    Cbor(ciborium::ser::Error<std::io::Error>),
}

impl fmt::Display for SerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerializationError::Io(e) => write!(f, "serialization IO error: {e}"),
            SerializationError::Cbor(e) => write!(f, "CBOR serialization error: {e}"),
        }
    }
}

impl std::error::Error for SerializationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SerializationError::Io(e) => Some(e),
            SerializationError::Cbor(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::format::SerializationFormat;
    use crate::record::MetricRecord;
    use crate::test_utils::{ARBITRARY_POLICY_1, TestEndpoint};

    /// Verify the querylog JSON wire format contains named metric keys
    /// produced by the metrique_writer Entry implementation.
    #[test]
    fn querylog_wire_format_shape() {
        let endpoint = TestEndpoint::new();
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        let output = String::from_utf8(records[0].clone()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        let obj = json.as_object().unwrap();

        // Top-level structure: timestamp, metrics, properties
        assert!(obj.contains_key("timestamp"), "missing timestamp");
        assert!(obj.contains_key("metrics"), "missing metrics");
        assert!(obj.contains_key("properties"), "missing properties");

        let metrics = obj["metrics"].as_object().unwrap();
        let properties = obj["properties"].as_object().unwrap();

        // Attribution goes into properties
        assert_eq!(properties["platform"], "test_server");
        assert_eq!(properties["resource"], "test_resource");

        // Fixed metric fields
        assert!(
            metrics.contains_key("handshake_count"),
            "missing handshake_count"
        );
        assert!(
            metrics.contains_key("sslv2_client_hello"),
            "missing sslv2_client_hello"
        );

        // Named metric keys from the Entry impl
        let has_negotiated_cipher = metrics.keys().any(|k| k.starts_with("cipher.negotiated."));
        let has_negotiated_version = metrics.keys().any(|k| k.starts_with("version.negotiated."));
        assert!(has_negotiated_cipher, "missing cipher.negotiated.* key");
        assert!(has_negotiated_version, "missing version.negotiated.* key");
    }

    /// CBOR roundtrip: serialize to CBOR via serde, deserialize back,
    /// and confirm the record is preserved.
    #[test]
    fn cbor_roundtrip() {
        let endpoint = TestEndpoint::with_format(SerializationFormat::Cbor);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        let cbor_record: MetricRecord = ciborium::from_reader(&records[0][..]).unwrap();

        // Re-serialize and deserialize to confirm stability
        let cbor_bytes = SerializationFormat::Cbor.serialize(&cbor_record).unwrap();
        let roundtripped: MetricRecord = ciborium::from_reader(&cbor_bytes[..]).unwrap();

        assert_eq!(cbor_record, roundtripped);
    }
}
