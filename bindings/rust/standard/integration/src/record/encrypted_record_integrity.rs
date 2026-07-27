// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verify that any bit-flip mutation in an encrypted TLS application data
//! record causes decryption to fail.

use crate::capability_check::{required_capability, Capability};
use s2n_tls::{
    config,
    security::Policy,
    testing::{self, TestPair},
};
use std::{io::Write, task::Poll};

const APP_DATA: &[u8] = b"hello";
const APP_DATA_LEN: usize = APP_DATA.len();

/// Perform a handshake, have the server send application data, and return the
/// pair along with the encrypted record bytes from the wire.
fn encrypted_record(config: &config::Config) -> (TestPair, Vec<u8>) {
    let mut pair = TestPair::from_config(config);
    pair.handshake().unwrap();

    assert!(matches!(
        pair.server.poll_send(APP_DATA),
        Poll::Ready(Ok(APP_DATA_LEN))
    ));

    let record: Vec<u8> = pair.io.server_tx_stream.borrow_mut().drain(..).collect();
    (pair, record)
}

/// Assert that flipping any single bit in an encrypted record is rejected.
fn assert_all_mutations_rejected(config: &config::Config) {
    // Verify the unmodified record decrypts successfully.
    let (mut pair, record) = encrypted_record(config);
    let mut buf = [0u8; 128];
    pair.io
        .server_tx_stream
        .borrow_mut()
        .write_all(&record)
        .unwrap();
    assert!(matches!(
        pair.client.poll_recv(&mut buf),
        Poll::Ready(Ok(APP_DATA_LEN))
    ),);

    let record_len = record.len();
    for bit in 0..record_len * 8 {
        let (mut pair, record) = encrypted_record(config);
        // sanity check: all of the records should be the same length
        assert_eq!(record.len(), record_len);

        let mut mutated = record;
        mutated[bit / 8] ^= 1 << (bit % 8);

        pair.io
            .server_tx_stream
            .borrow_mut()
            .write_all(&mutated)
            .unwrap();

        let mut recv_buf = [0u8; 128];
        match pair.client.poll_recv(&mut recv_buf) {
            Poll::Ready(Err(e)) => {
                const ALLOWED_ERRORS: &[&str] = &[
                    "S2N_ERR_BAD_MESSAGE",
                    "S2N_ERR_DECRYPT",
                    "S2N_ERR_SAFETY",
                    "S2N_ERR_STUFFER_OUT_OF_DATA",
                    "S2N_ERR_INTEGER_OVERFLOW",
                ];
                let name = e.name();
                assert!(ALLOWED_ERRORS.contains(&name), "unexpected error {name}");
            }
            Poll::Ready(Ok(_)) => panic!("accepted record for bit flip {bit}"),
            Poll::Pending => {
                // not ideal, but our support of SSLv2 client hellos means that
                // we go down a different record parsing path.
                // https://github.com/aws/s2n-tls/issues/6001
                // s2n-tls returns poll pending because some of the header bytes
                // get confused for the record length and it thinks more data is
                // coming.
            }
        };
    }
}

// TLS 1.3 aead cipher
#[test]
fn tls13_aead() {
    required_capability(&[Capability::Tls13], || {
        let config =
            testing::build_config(&Policy::from_version("default_tls13").unwrap()).unwrap();

        let (pair, _) = encrypted_record(&config);
        let cipher = pair.server.cipher_suite().unwrap();
        assert_eq!(cipher, "TLS_AES_128_GCM_SHA256");

        assert_all_mutations_rejected(&config);
    });
}

// TLS 1.2 stream cipher
#[test]
fn tls12_rc4() {
    required_capability(&[Capability::Rc4], || {
        let config =
            testing::build_config(&Policy::from_version("test_all_tls12").unwrap()).unwrap();

        let (pair, _) = encrypted_record(&config);
        let cipher = pair.server.cipher_suite().unwrap();
        assert_eq!(cipher, "RC4-MD5");

        assert_all_mutations_rejected(&config);
    });
}

// TLS 1.2 block cipher
#[test]
fn tls12_cbc() {
    let config = testing::build_config(&Policy::from_version("20140601").unwrap()).unwrap();

    let (pair, _) = encrypted_record(&config);
    let cipher = pair.server.cipher_suite().unwrap();
    assert_eq!(cipher, "AES128-SHA256");

    assert_all_mutations_rejected(&config);
}
