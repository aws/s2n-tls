// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{
    security::Policy,
    testing::{self, TestPair},
};
use std::task::Poll;

/// Policy arbitrarily selected to negotiate TLS 1.2. We negotiate TLS 1.2 as a
/// convenience to avoid the TLS 1.3 required capability logic.
const TEST_POLICY: &str = "20240501";

/// An arbitrarily chosen record payload, far less than the max record payload
const PAYLOAD: &[u8; PAYLOAD_SIZE] = &[1; PAYLOAD_SIZE];
const PAYLOAD_SIZE: usize = 256;
/// The final size of a TLS 1.2 record containing [`PAYLOAD_SIZE`]
const ENCAPSULATED_SIZE: usize = 285;

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

struct IOScenario {
    /// used to setup the scenario, e.g. "load" records or fragments onto the wire
    pair_setup: fn(&mut TestPair),
    /// called with a server that does not have receive buffering enabled
    default_io_assertions: fn(&mut TestPair),
    /// called with a server that has receive buffering enabled
    buffered_io_assertions: fn(&mut TestPair),
}

impl IOScenario {
    fn execute(self) {
        println!("checking standard IO");
        let mut pair = new_pair();
        (self.pair_setup)(&mut pair);
        (self.default_io_assertions)(&mut pair);

        println!("checking buffered recv IO");
        let mut pair = new_buffered_recv_pair();
        (self.pair_setup)(&mut pair);
        (self.buffered_io_assertions)(&mut pair);
    }

    /// use this to construct an IO scenario where the buffered and default cases
    /// should have the same behavior.
    fn same_behavior(pair_setup: fn(&mut TestPair), io_assertions: fn(&mut TestPair)) -> Self {
        Self {
            pair_setup,
            default_io_assertions: io_assertions,
            buffered_io_assertions: io_assertions,
        }
    }
}

/// s2n-tls has a separate buffer for record headers, so we test the behavior as
/// a different mode than a plain "incomplete record"
#[test]
fn read_incomplete_header() {
    let io = IOScenario::same_behavior(
        |pair| {
            assert!(pair.client.poll_send(PAYLOAD).is_ready());

            // Leave only 2 bytes available (incomplete 5-byte header)
            let stream = &pair.io.client_tx_stream;
            stream.borrow_mut().truncate(2);
        },
        |pair| {
            let result = pair.server.poll_recv(&mut [0; PAYLOAD_SIZE]);
            assert!(matches!(result, Poll::Pending));
            assert_eq!(pair.server.peek_len(), 0);
            assert_eq!(pair.server.peek_buffered_len(), 0);
        },
    );
    io.execute();
}

#[test]
fn read_incomplete_record() {
    let io = IOScenario::same_behavior(
        |pair| {
            assert!(pair.client.poll_send(PAYLOAD).is_ready());

            // remove the last byte (incomplete record)
            pair.io.client_tx_stream.borrow_mut().pop_back().unwrap();
        },
        |pair| {
            let result = pair.server.poll_recv(&mut [0; PAYLOAD_SIZE]);
            assert!(matches!(result, Poll::Pending));
            assert_eq!(pair.server.peek_len(), 0);
            assert_eq!(pair.server.peek_buffered_len(), 0);
        },
    );
    io.execute();
}

#[test]
fn read_complete_record() {
    let io = IOScenario::same_behavior(
        |pair| {
            assert!(pair.client.poll_send(PAYLOAD).is_ready());
        },
        |pair| {
            let mut buf = [0u8; PAYLOAD_SIZE];
            let result = pair.server.poll_recv(&mut buf);
            assert!(matches!(result, Poll::Ready(Ok(PAYLOAD_SIZE))));
            assert_eq!(&buf[..PAYLOAD_SIZE], PAYLOAD);
            assert_eq!(pair.server.peek_len(), 0);
            assert_eq!(pair.server.peek_buffered_len(), 0);
        },
    );
    io.execute();
}

/// When a small application buffer is used, poll_recv will return the size of
/// the buffer, and peek_len will return the remaining data to be read.
#[test]
fn read_complete_record_with_small_application_buffer() {
    /// one quarter of the size of the payload
    const SMALL_BUFFER_SIZE: usize = PAYLOAD_SIZE.div_ceil(4);

    let io = IOScenario::same_behavior(
        |pair| {
            assert!(pair.client.poll_send(PAYLOAD).is_ready());
        },
        |pair| {
            let mut buf = [0u8; SMALL_BUFFER_SIZE];
            let result = pair.server.poll_recv(&mut buf);
            assert!(matches!(result, Poll::Ready(Ok(SMALL_BUFFER_SIZE))));
            assert_eq!(pair.server.peek_len(), PAYLOAD_SIZE - SMALL_BUFFER_SIZE);
            assert_eq!(pair.server.peek_buffered_len(), 0);
        },
    );
    io.execute();
}

/// When there are multiple records available on the wire, IO depends on the configured
/// IO behavior.
///
/// In all cases, poll_recv will only ever decapsulate one record at a time. However
/// if recv_buffering is enabled than all of the bytes will be read off the wire
#[test]
fn read_two_complete_records() {
    let io = IOScenario {
        pair_setup: |pair| {
            assert!(pair.client.poll_send(PAYLOAD).is_ready());
            assert!(pair.client.poll_send(PAYLOAD).is_ready());
        },
        default_io_assertions: |pair| {
            let mut buf = [0u8; PAYLOAD_SIZE * 2];
            let result = pair.server.poll_recv(&mut buf);
            assert!(matches!(result, Poll::Ready(Ok(PAYLOAD_SIZE))));
            assert_eq!(pair.server.peek_len(), 0);
            assert_eq!(pair.server.peek_buffered_len(), 0);
            // the second record is still on the wire
            assert_eq!(pair.io.client_tx_stream.borrow().len(), ENCAPSULATED_SIZE);
        },
        buffered_io_assertions: |pair| {
            let mut buf = [0u8; PAYLOAD_SIZE * 2];
            let result = pair.server.poll_recv(&mut buf);
            assert!(matches!(result, Poll::Ready(Ok(PAYLOAD_SIZE))));
            assert_eq!(pair.server.peek_len(), 0);
            // the second record is in the connection buffer
            assert_eq!(pair.server.peek_buffered_len(), ENCAPSULATED_SIZE);
            assert!(pair.io.client_tx_stream.borrow().is_empty());
        },
    };
    io.execute();
}

/// This test demonstrates an unfortunate behavior of `peek_buffered`, where data
/// appears to disappear if it's a record fragment.
#[test]
fn read_complete_record_and_fragment() {
    let io = IOScenario {
        pair_setup: |pair| {
            assert!(pair.client.poll_send(PAYLOAD).is_ready());
            assert!(pair.client.poll_send(PAYLOAD).is_ready());
            // drop the last byte, so the second record is a fragment
            pair.io.client_tx_stream.borrow_mut().pop_back().unwrap();
        },
        default_io_assertions: |pair| {
            let mut buf = [0u8; PAYLOAD_SIZE * 2];
            let result = pair.server.poll_recv(&mut buf);
            assert!(matches!(result, Poll::Ready(Ok(PAYLOAD_SIZE))));
            assert_eq!(pair.server.peek_len(), 0);
            assert_eq!(pair.server.peek_buffered_len(), 0);
            // the record fragment is on the wire
            assert_eq!(
                pair.io.client_tx_stream.borrow().len(),
                ENCAPSULATED_SIZE - 1
            );
        },
        buffered_io_assertions: |pair| {
            let mut buf = [0u8; PAYLOAD_SIZE * 2];
            let result = pair.server.poll_recv(&mut buf);
            assert!(matches!(result, Poll::Ready(Ok(PAYLOAD_SIZE))));
            assert_eq!(pair.server.peek_len(), 0);
            // we report that there is buffered data
            assert_eq!(pair.server.peek_buffered_len(), ENCAPSULATED_SIZE - 1);
            assert!(pair.io.client_tx_stream.borrow().is_empty());

            // but after the next call to poll recv it is effectively hidden because
            // we don't surface any apis to inspect buffered record fragments
            assert!(pair.server.poll_recv(&mut [0]).is_pending());
            assert_eq!(pair.server.peek_len(), 0);
            assert_eq!(pair.server.peek_buffered_len(), 0);
        },
    };
    io.execute();
}
