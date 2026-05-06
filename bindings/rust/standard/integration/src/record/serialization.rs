// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{
    enums::SerializationVersion,
    error::ErrorType,
    security::Policy,
    testing::{self, TestPair},
};
use std::task::Poll;

/// The TLS record header is 5 bytes: 1 (content type) + 2 (protocol version) + 2 (length)
const TLS_RECORD_HEADER_LEN: usize = 5;

/// Policy arbitrarily selected to negotiate TLS 1.2. We negotiate TLS 1.2 as a 
/// convenience to avoid the TLS 1.3 required capability logic.
const TEST_POLICY: &str = "20240501";

fn build_serializable_config() -> s2n_tls::config::Config {
    let mut builder =
        testing::config_builder(&Policy::from_version(TEST_POLICY).unwrap()).unwrap();
    builder
        .set_serialization_version(SerializationVersion::V1)
        .unwrap();
    builder.build().unwrap()
}

fn assert_invalid_state_error(err: s2n_tls::error::Error) {
    assert_eq!(err.kind(), ErrorType::UsageError);
    assert_eq!(err.name(), "S2N_ERR_INVALID_STATE");
    assert_eq!(
        err.message(),
        "Invalid state, this is the result of invalid use of an API. \
         Check the API documentation for the function that raised this error for more info"
    );
}

/// Attempt to serialize the connection. Returns the result.
fn try_serialize(conn: &s2n_tls::connection::Connection) -> Result<(), s2n_tls::error::Error> {
    let length = conn.serialization_length()?;
    let mut buf = vec![0u8; length];
    conn.serialize(&mut buf)
}

/// This test servers as documentation/confirmation of some sharp edges around
/// serialization failure. Specifically, there is no detecting whether a record
/// fragment has been ingested. https://github.com/aws/s2n-tls/issues/5863
#[test]
fn serialization_io_edge_cases() {
    let config = build_serializable_config();

    // case 1: buffer contains incomplete header
    // s2n-tls has a separate buffer for header so we test this separately from
    // the "partial record" case.
    {
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();

        // Client sends data, producing encrypted TLS records in client_tx_stream
        assert!(pair.client.poll_send(&[0; 100]).is_ready());

        // Truncate the buffer to only 2 bytes (incomplete 5-byte header)
        pair.io.client_tx_stream.borrow_mut().truncate(2);

        // Server attempts to read but only gets a partial header
        assert!(matches!(
            pair.server.poll_recv(&mut [0; 100]),
            Poll::Pending
        ));
        // This is "invisible" data, not yet decrypted
        assert_eq!(pair.server.peek_len(), 0);

        // Serialization must fail because header_in has pending data
        assert_invalid_state_error(try_serialize(&pair.server).unwrap_err());
    }

    // case 2: buffer contains partial record, waiting for complete record
    {
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();

        // Client sends data
        assert!(pair.client.poll_send(&[0; 100]).is_ready());

        // Truncate the buffer to header + 1 byte of body (partial record)
        pair.io
            .client_tx_stream
            .borrow_mut()
            .truncate(TLS_RECORD_HEADER_LEN + 1);

        // Server attempts to read but only gets a partial record
        assert!(matches!(
            pair.server.poll_recv(&mut [0; 100]),
            Poll::Pending
        ));
        // This is "invisible" data, not yet decrypted
        assert_eq!(pair.server.peek_len(), 0);

        // Serialization must fail because conn->in has pending partial record data
        assert_invalid_state_error(try_serialize(&pair.server).unwrap_err());
    }

    // case 3: buffer contains decrypted record, waiting for application read
    {
        let mut pair = TestPair::from_config(&config);
        pair.handshake().unwrap();

        // Client sends data
        assert!(pair.client.poll_send(&[0; 100]).is_ready());

        // Server reads with a 1-byte buffer: decrypts the full record but only
        // returns 1 byte to the application, leaving the rest buffered internally
        assert!(matches!(
            pair.server.poll_recv(&mut [0; 1]),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(pair.server.peek_len(), 99);

        // Serialization must fail because conn->in has pending decrypted data
        assert_invalid_state_error(try_serialize(&pair.server).unwrap_err());

        // read the rest of the data, serialization then succeeds
        assert!(pair.server.poll_recv(&mut [0; 100]).is_ready());
        assert!(pair.server.serialize(&mut [0; 1_024]).is_ok());
    }
}
