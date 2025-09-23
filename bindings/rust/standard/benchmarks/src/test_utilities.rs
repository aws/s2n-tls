// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::ErrorKind;

use tls_harness::{harness::TlsInfo, SigType, TlsConnection};

use crate::{new_bench_pair, CipherSuite, CryptoConfig, HandshakeType, KXGroup, TlsBenchConfig};
use strum::IntoEnumIterator;

/// Transfer a large amount of application data
pub fn transfer<T>()
where
    T: TlsConnection,
    T::Config: TlsBenchConfig,
{
    // use a large buffer to test across TLS record boundaries
    let mut buf = [0x56u8; 1000000];
    for cipher_suite in CipherSuite::iter() {
        let crypto_config = CryptoConfig::new(cipher_suite, KXGroup::default(), SigType::default());
        let mut conn_pair =
            new_bench_pair::<T, T>(crypto_config, HandshakeType::default()).unwrap();
        conn_pair.handshake().unwrap();
        conn_pair.round_trip_transfer(&mut buf).unwrap();
        conn_pair.shutdown().unwrap();
    }
}

/// Perform all of the different handshake types across a permutation of ciphers,
/// key exchange groups, and certificate types.
pub fn all_handshakes<T>()
where
    T: TlsConnection + TlsInfo,
    T::Config: TlsBenchConfig,
{
    for handshake_type in HandshakeType::iter() {
        for cipher_suite in CipherSuite::iter() {
            for kx_group in KXGroup::iter() {
                for sig_type in SigType::iter() {
                    let crypto_config = CryptoConfig::new(cipher_suite, kx_group, sig_type);
                    let mut conn_pair =
                        new_bench_pair::<T, T>(crypto_config, handshake_type).unwrap();

                    assert!(!conn_pair.handshake_completed());
                    conn_pair.handshake().unwrap();
                    assert!(conn_pair.handshake_completed());

                    assert!(conn_pair.negotiated_tls13());
                    assert_eq!(
                        format!("{cipher_suite:?}"),
                        conn_pair.get_negotiated_cipher_suite()
                    );
                    match handshake_type {
                        HandshakeType::ServerAuth => {
                            assert!(!conn_pair.server.mutual_auth());
                            assert!(!conn_pair.server.resumed_connection());
                        }
                        HandshakeType::MutualAuth => {
                            assert!(conn_pair.server.mutual_auth());
                            assert!(!conn_pair.server.resumed_connection());
                        }
                        HandshakeType::Resumption => {
                            assert!(!conn_pair.server.mutual_auth());
                            assert!(conn_pair.server.resumed_connection());
                        }
                    }

                    // read in "application data" handshake messages.
                    // "NewSessionTicket" in the case of resumption
                    let err = conn_pair.client_mut().recv(&mut [0]).unwrap_err();
                    assert_eq!(err.kind(), ErrorKind::WouldBlock);

                    conn_pair.shutdown().unwrap();
                }
            }
        }
    }
}
