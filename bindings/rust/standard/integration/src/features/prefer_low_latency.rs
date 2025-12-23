use openssl::ssl::SslContextBuilder;
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair,
};
/// Integration test for the feature: s2n_connection_prefer_low_latency()
///
/// "Prefer low latency" should cause s2n-tls to use small record sizes for
/// application data. This is a wire-format behavior change, so we assert
/// on record sizes.

const SMALL_RECORD_MAX: usize = 1_500;
const APP_DATA_SIZE: usize = 100_000;

fn assert_all_small(record_sizes: &[u16]) {
    // Skip final trailing partial record like the dynamic sizing test does.
    let sizes = if record_sizes.len() > 1 {
        &record_sizes[..record_sizes.len() - 1]
    } else {
        record_sizes
    };

    assert!(!sizes.is_empty());

    for &size in sizes {
        assert!(
            size as usize <= SMALL_RECORD_MAX,
        );
    }
}

#[test]
fn s2n_server_case() {
    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
        let configs =
            TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
        configs.connection_pair()
    };

    pair.server.connection_mut().prefer_low_latency().unwrap();
    pair.handshake().unwrap();

    // Only capture application data records.
    pair.io.enable_recording();

    pair.round_trip_assert(APP_DATA_SIZE).unwrap();
    let sizes = pair.io.server_record_sizes();
    assert_all_small(&sizes);

    pair.shutdown().unwrap();
}

#[test]
fn s2n_client_case() {
    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = {
        let configs =
            TlsConfigBuilderPair::<s2n_tls::config::Builder, SslContextBuilder>::default();
        configs.connection_pair()
    };

    pair.client.connection_mut().prefer_low_latency().unwrap();
    pair.handshake().unwrap();

    pair.io.enable_recording();

    pair.round_trip_assert(APP_DATA_SIZE).unwrap();
    let sizes = pair.io.client_record_sizes();
    assert_all_small(&sizes);

    pair.shutdown().unwrap();
}
