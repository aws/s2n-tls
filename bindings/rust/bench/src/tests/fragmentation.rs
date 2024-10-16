use crate::{
    openssl_extension::SslContextExtension, s2n_tls::S2NConfig, tests::TestUtils,
    OpenSslConnection, S2NConnection, TlsConnPair,
};

use super::ConfigPair;

/// Feature: s2n_connection_prefer_low_latency()
/// 
/// "Prefer low latency" causes s2n-tls to use smaller record sizes. This is a wire
/// format change, so we use an integration test to make sure things remain correct.
#[test]
fn prefer_low_latency() {
    let (ossl_config, s2n_config) =
    ConfigPair::<crate::openssl::OpenSslConfig, S2NConfig>::default().split();

    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
        TlsConnPair::from_configs(&ossl_config, &s2n_config);

    // configure s2n-tls server connection to prefer low latency
    pair.server.connection.prefer_low_latency().unwrap();

    assert!(pair.handshake().is_ok());
    assert!(pair.round_trip_assert(16_000).is_ok());
}

/// Correctness: s2n-tls correctly handles different record sizes
/// 
/// We configure an openssl client to use a variety of record sizes to confirm
/// that s2n-tls correctly handles the differently sized records. This is done by
/// with the `SSL_CTX_set_max_send_fragment` openssl API.
/// https://docs.openssl.org/3.0/man3/SSL_CTX_set_split_send_fragment/#synopsis
#[test]
fn fragmentation() {
    const FRAGMENT_TEST_CASES: [usize; 5] = [512, 2048, 8192, 12345, 16384];

    fn test_case(client_frag_length: usize) {
        let (mut ossl_config, s2n_config) =
            ConfigPair::<crate::openssl::OpenSslConfig, S2NConfig>::default().split();
    
        ossl_config.config.set_max_send_fragment(client_frag_length);
    
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
            TlsConnPair::from_configs(&ossl_config, &s2n_config);
    
        assert!(pair.handshake().is_ok());
        assert!(pair.round_trip_assert(16_000).is_ok());
    }

    FRAGMENT_TEST_CASES
        .into_iter()
        .for_each(|frag_length| test_case(frag_length));
}
