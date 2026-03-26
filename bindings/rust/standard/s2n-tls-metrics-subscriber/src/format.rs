// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::record::MetricRecord;
use std::fmt;

/// Determines how a [`MetricRecord`] is serialized before being written to a Sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationFormat {
    /// Querylog JSON format (via `serde_json`)
    Querylog,
    /// CBOR binary format (via `ciborium`)
    Cbor,
}

impl SerializationFormat {
    /// Serialize a `MetricRecord` into bytes using this format.
    pub(crate) fn serialize(&self, record: &MetricRecord) -> Result<Vec<u8>, SerializationError> {
        match self {
            SerializationFormat::Querylog => {
                serde_json::to_vec(record).map_err(SerializationError::Json)
            }
            SerializationFormat::Cbor => {
                let mut buf = Vec::new();
                ciborium::into_writer(record, &mut buf).map_err(SerializationError::Cbor)?;
                Ok(buf)
            }
        }
    }
}

/// Errors that can occur during metric record serialization.
#[derive(Debug)]
pub enum SerializationError {
    /// JSON serialization error
    Json(serde_json::Error),
    /// CBOR serialization error
    Cbor(ciborium::ser::Error<std::io::Error>),
}

impl fmt::Display for SerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerializationError::Json(e) => write!(f, "JSON serialization error: {e}"),
            SerializationError::Cbor(e) => write!(f, "CBOR serialization error: {e}"),
        }
    }
}

impl std::error::Error for SerializationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SerializationError::Json(e) => Some(e),
            SerializationError::Cbor(e) => Some(e),
        }
    }
}

impl From<serde_json::Error> for SerializationError {
    fn from(err: serde_json::Error) -> Self {
        SerializationError::Json(err)
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for SerializationError {
    fn from(err: ciborium::ser::Error<std::io::Error>) -> Self {
        SerializationError::Cbor(err)
    }
}
