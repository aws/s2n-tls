// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{
    security::Policy,
    testing::{self, TestPair},
};
use std::task::Poll;

/// The TLS record header is 5 bytes
const TLS_RECORD_HEADER_LEN: usize = 5;

/// Policy arbitrarily selected to negotiate TLS 1.2. We negotiate TLS 1.2 as a 
/// convenience to avoid the TLS 1.3 required capability logic.
const TEST_POLICY: &str = "20240501";

fn new_pair() -> TestPair {
    let config = testing::build_config(&Policy::from_version(TEST_POLICY).unwrap()).unwrap();
    let mut pair = TestPair::from_config(&config);
    pair.handshake().unwrap();
    pair
}

fn new_buffered_recv_pair() -> TestPair {
    let config = testing::build_config(&Policy::from_version(TEST_POLICY).unwrap()).unwrap();
    let mut pair = TestPair::from_config(&config);
    pair.server.set_receive_buffering(true).unwrap();
    pair.handshake().unwrap();
    pair
}

#[test]
fn read_behaviors_with_standard_io() {
    // read incomplete header
    {
        let mut pair = new_pair();
        assert!(pair.client.poll_send(&[1; 100]).is_ready());

        // Leave only 2 bytes available (incomplete 5-byte header)
        pair.io.client_tx_stream.borrow_mut().truncate(2);

        let result = pair.server.poll_recv(&mut [0; 100]);
        assert!(pair.io.client_tx_stream.borrow().is_empty());
        assert!(matches!(result, Poll::Pending));
        assert_eq!(pair.server.peek_len(), 0);
        assert_eq!(pair.server.peek_buffered_len(), 0);
    }

    // read incomplete record
    {
        let mut pair = new_pair();
        assert!(pair.client.poll_send(&[2; 100]).is_ready());

        // Leave header + 1 byte of body (incomplete record)
        pair.io
            .client_tx_stream
            .borrow_mut()
            .truncate(TLS_RECORD_HEADER_LEN + 1);

        let result = pair.server.poll_recv(&mut [0; 100]);
        assert!(matches!(result, Poll::Pending));
        assert_eq!(pair.server.peek_len(), 0);
        assert_eq!(pair.server.peek_buffered_len(), 0);
    }

    // read complete record
    {
        let mut pair = new_pair();
        assert!(pair.client.poll_send(&[1; 100]).is_ready());

        let mut buf = [0u8; 200];
        let result = pair.server.poll_recv(&mut buf);
        assert!(matches!(result, Poll::Ready(Ok(100))));
        assert_eq!(&buf[..100], &[1; 100]);
        assert_eq!(pair.server.peek_len(), 0);
        assert_eq!(pair.server.peek_buffered_len(), 0);
    }

    // read complete record off wire, application buffer too small for full record
    {
        let mut pair = new_pair();
        assert!(pair.client.poll_send(&[1; 100]).is_ready());

        // Read with a buffer smaller than the record payload
        let mut buf = [0u8; 10];
        let result = pair.server.poll_recv(&mut buf);
        assert!(matches!(result, Poll::Ready(Ok(10))));
        assert_eq!(&buf, &[1; 10]);
        // Remaining decrypted data is available via peek
        assert_eq!(pair.server.peek_len(), 90);
        assert_eq!(pair.server.peek_buffered_len(), 0);
    }

    // read complete record off wire, pending record in wire buffer, application
    // buffer large enough for more data
    {
        let mut pair = new_pair();
        // Send two separate records
        assert!(pair.client.poll_send(&[1; 100]).is_ready());
        assert!(pair.client.poll_send(&[2; 100]).is_ready());

        // Application buffer is large enough for both records, but only one record
        // is read. The other remains on the wire.
        let mut buf = [0u8; 200];
        let result = pair.server.poll_recv(&mut buf);
        assert!(matches!(result, Poll::Ready(Ok(100))));
        assert_eq!(&buf[..100], &[1; 100]);
        // 129 -> 100 byte record + header/auth overhead
        assert_eq!(pair.io.client_tx_stream.borrow().len(), 129);
        assert_eq!(pair.server.peek_len(), 0);
        assert_eq!(pair.server.peek_buffered_len(), 0);

        // A second poll_recv is needed to read the next record
        let result = pair.server.poll_recv(&mut buf);
        assert!(matches!(result, Poll::Ready(Ok(100))));
        assert_eq!(&buf[..100], &[2; 100]);
        assert_eq!(pair.server.peek_len(), 0);
        assert_eq!(pair.server.peek_buffered_len(), 0);
    }
}

#[test]
fn read_behaviors_with_buffered_io() {
    // read incomplete header
    {
        let mut pair = new_buffered_recv_pair();
        assert!(pair.client.poll_send(&[1; 100]).is_ready());

        // Leave only 2 bytes available (incomplete 5-byte header)
        let stream = &pair.io.client_tx_stream;
        stream.borrow_mut().truncate(2);

        let result = pair.server.poll_recv(&mut [0; 100]);
        assert!(matches!(result, Poll::Pending));
        assert_eq!(pair.server.peek_len(), 0);
        assert_eq!(pair.server.peek_buffered_len(), 0);
    }

    // read incomplete record
    {
        let mut pair = new_buffered_recv_pair();
        assert!(pair.client.poll_send(&[1; 100]).is_ready());

        // Leave header + 1 byte of body (incomplete record)
        let stream = &pair.io.client_tx_stream;
        stream.borrow_mut().truncate(TLS_RECORD_HEADER_LEN + 1);

        let result = pair.server.poll_recv(&mut [0; 100]);
        assert!(matches!(result, Poll::Pending));
        assert_eq!(pair.server.peek_len(), 0);
        assert_eq!(pair.server.peek_buffered_len(), 0);
    }

    // read complete record
    {
        let mut pair = new_buffered_recv_pair();
        assert!(pair.client.poll_send(&[1; 100]).is_ready());

        let mut buf = [0u8; 200];
        let result = pair.server.poll_recv(&mut buf);
        assert!(matches!(result, Poll::Ready(Ok(100))));
        assert_eq!(&buf[..100], &[1; 100]);
        assert_eq!(pair.server.peek_len(), 0);
        assert_eq!(pair.server.peek_buffered_len(), 0);
    }

    // read complete record off wire, application buffer too small for full record
    {
        let mut pair = new_buffered_recv_pair();
        assert!(pair.client.poll_send(&[1; 100]).is_ready());

        // Read with a buffer smaller than the record payload
        let mut buf = [0u8; 10];
        let result = pair.server.poll_recv(&mut buf);
        assert!(matches!(result, Poll::Ready(Ok(10))));
        assert_eq!(&buf, &[1; 10]);
        // Remaining decrypted data is available via peek
        assert_eq!(pair.server.peek_len(), 90);
        assert_eq!(pair.server.peek_buffered_len(), 0);
    }

    // read complete record off wire, pending record in wire buffer, application
    // buffer large enough for more data
    {
        let mut pair = new_buffered_recv_pair();
        // Send two separate records
        assert!(pair.client.poll_send(&[1; 100]).is_ready());
        assert!(pair.client.poll_send(&[2; 100]).is_ready());

        let mut buf = [0u8; 200];
        let result = pair.server.poll_recv(&mut buf);
        // both records were read off the wire, only one was decrypted
        assert!(matches!(result, Poll::Ready(Ok(100))));
        assert_eq!(&buf[..100], &[1; 100]);
        assert_eq!(pair.server.peek_len(), 0);
        // the second record is internally buffered, but not decrypted
        assert_eq!(pair.server.peek_buffered_len(), 129);

        let result = pair.server.poll_recv(&mut buf);
        assert!(matches!(result, Poll::Ready(Ok(100))));
        assert_eq!(&buf[..100], &[2; 100]);
        assert_eq!(pair.server.peek_len(), 0);
        assert_eq!(pair.server.peek_buffered_len(), 0);
    }
}
