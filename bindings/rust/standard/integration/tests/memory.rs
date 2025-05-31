// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// dhat can only be run in a single thread, so we use a single test case in an
// "integration" test (tests/*) to fulfill those conditions.

use std::task::Poll;

use s2n_tls::error::Error as S2NError;
use s2n_tls::{
    security::Policy,
    testing::{self, TestPair},
};

/// Return an estimation of the memory size of the IO buffers
///
/// This isn't totally accurate because it doesn't account for any indirection that
/// may be present.
fn test_pair_io_size(pair: &TestPair) -> usize {
    pair.io.client_tx_stream.borrow().capacity() + pair.io.server_tx_stream.borrow().capacity()
}

fn fuzzy_equals(actual: usize, expected: usize) -> bool {
    const TOLERANCE: usize = 100;

    println!("actual: {actual}, expected: {expected}");
    actual < expected + TOLERANCE && actual > expected - TOLERANCE
}

/// Note that this does not detect total memory usage, only the memory usage that
/// uses the rust allocator.
///
/// Because the s2n-tls rust bindings set the s2n-tls memory callbacks to use the
/// rust allocator, this does give a good picture of s2n-tls allocations. However
/// this will _not_ report the allocations done by the libcrypto.
///
/// It's important to keep allocations to a minimal amount in this test to give
/// as accurate a picture as possible into s2n-tls memory usage at various stages
/// in the connection lifecycle. We should limit this to
/// - config
/// - client connection
/// - server connection
/// - TestPair io buffers
#[test]
fn memory_consumption() -> Result<(), S2NError> {
    const CLIENT_MESSAGE: &[u8] = b"from client";
    const SERVER_MESSAGE: &[u8] = b"from server";

    let _profiler = dhat::Profiler::new_heap();
    let config = testing::build_config(&Policy::from_version("default_tls13")?).unwrap();

    let stats = dhat::HeapStats::get();
    let config_init = stats.curr_bytes;

    let mut pair = TestPair::from_config(&config);
    let connection_init = dhat::HeapStats::get().curr_bytes - test_pair_io_size(&pair);

    // manually drive the handshake forward to get a measurement while the handshake
    // is in flight
    assert!(matches!(pair.client.poll_negotiate(), Poll::Pending));
    assert!(matches!(pair.server.poll_negotiate(), Poll::Pending));

    let handshake_in_progress = dhat::HeapStats::get().curr_bytes - test_pair_io_size(&pair);

    pair.handshake()?;
    let handshake_complete = dhat::HeapStats::get().curr_bytes - test_pair_io_size(&pair);

    let _ = pair.client.poll_send(CLIENT_MESSAGE);
    let _ = pair.server.poll_send(SERVER_MESSAGE);
    let _ = pair.client.poll_recv(&mut [0; SERVER_MESSAGE.len()]);
    let _ = pair.server.poll_recv(&mut [0; CLIENT_MESSAGE.len()]);
    let application_data = dhat::HeapStats::get().curr_bytes - test_pair_io_size(&pair);

    println!("config: {config_init}");
    println!("connection_init: {connection_init}");
    println!("handshake in progress: {handshake_in_progress}");
    println!("handshake complete: {handshake_complete}");
    println!("application data: {application_data}");

    assert!(fuzzy_equals(config_init, 5086));
    assert!(fuzzy_equals(connection_init, 54440));
    assert!(fuzzy_equals(handshake_in_progress, 104911));
    assert!(fuzzy_equals(handshake_complete, 70085));
    assert!(fuzzy_equals(application_data, 70085));
    Ok(())
}
