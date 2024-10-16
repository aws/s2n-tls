use crate::{
    openssl::OpenSslConfig,
    openssl_extension::SslContextExtension,
    s2n_tls::S2NConfig,
    tests::{ConfigPair, TestUtils},
    OpenSslConnection, S2NConnection, TlsConnPair,
};

/// Correctness: s2n-tls correctly handles padded records
/// 
/// Record padding is new in TLS 1.3
/// 
/// We configure an openssl client to add pading records using 
/// `SSL_CTX_set_block_padding`. This function will pad records to a multiple
/// of the supplied `pad_to` size.
/// https://docs.openssl.org/1.1.1/man3/SSL_CTX_set_record_padding_callback/
#[test]
fn record_padding() {
    const SEND_SIZES: [usize; 6] = [1, 10, 100, 1_000, 5_000, 10_000];
    const PAD_TO_CASES: [usize; 4] = [512, 1_024, 4_096, 16_000];

    // we _could_ type erase the TlsConnPair, but it involves a decent amount of
    // boilerplate to Box<dyn> everything. For the time being, the duplication is
    // preferred.

    fn s2n_server_case(pad_to: usize) {
        let (mut ossl_config, s2n_config) = ConfigPair::<OpenSslConfig, S2NConfig>::default().split();
    
        ossl_config.config.set_block_padding(pad_to);
    
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
            TlsConnPair::from_configs(&ossl_config, &s2n_config);
    
        assert!(pair.handshake().is_ok());
        for send in SEND_SIZES {
            assert!(pair.round_trip_assert(send).is_ok());
        }
    }

    fn s2n_client_case(pad_to: usize) {
        let (s2n_config, mut ossl_config) = ConfigPair::<S2NConfig, OpenSslConfig>::default().split();
    
        ossl_config.config.set_block_padding(pad_to);
    
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
            TlsConnPair::from_configs(&s2n_config, &ossl_config);
    
        assert!(pair.handshake().is_ok());
        for send in SEND_SIZES {
            assert!(pair.round_trip_assert(send).is_ok());
        }
    }

    PAD_TO_CASES
        .into_iter()
        .for_each(|pad_to| {
            s2n_server_case(pad_to);
            s2n_client_case(pad_to);
        });
}
