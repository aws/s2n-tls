// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verify that any bit-flip mutation in an encrypted TLS application data
//! record causes decryption to fail.

use crate::capability_check::{required_capability, Capability};
use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256};
use s2n_tls::error::Error as S2NError;
use s2n_tls::{
    config,
    enums::Version,
    security::Policy,
    testing::{InsecureAcceptAllCertificatesHandler, TestPair},
};
use std::task::Poll;

fn tamper_bit(record: &mut [u8], bit_index: usize) -> bool {
    /// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5
    const APPLICATION_DATA: u8 = 23;

    // The version field of plaintext record headers is explicitly ignored per
    // RFC 8446 and RFC 5246, so flipping bits there won't cause a failure.
    let mut unprotected_bytes = Vec::new();
    let mut current = 0;
    while current < record.len() {
        // Record Header Layout
        // [*, *, *, *, *]
        //  0, 1, 2, 3, 4
        //          |----| length
        //    |----| version
        // |-| content type
        let content_type = record[current];
        let length = u16::from_be_bytes([record[current + 3], record[current + 4]]);

        if content_type != APPLICATION_DATA {
            // Only the version bytes (offsets 1, 2) in plaintext record headers
            // are unprotected
            unprotected_bytes.push(current + 1);
            unprotected_bytes.push(current + 2);
        }

        current += 5 + length as usize;
    }

    let byte_index = bit_index / 8;
    let bit_index = bit_index % 8;

    if unprotected_bytes.contains(&byte_index) {
        false
    } else {
        let byte_to_mutate = record.get_mut(byte_index).unwrap();
        *byte_to_mutate = *byte_to_mutate ^ (1 << bit_index);
        true
    }
}

/// Perform a handshake, returning the handshake transcript size and negotiated version
fn negotiation_check(config: &config::Config) -> (usize, Version) {
    let mut pair = TestPair::from_config(config);
    let mut transcript = 0;
    loop {
        let client_poll = pair.client.poll_negotiate();
        transcript += pair.io.client_tx_stream.borrow().len();

        let server_poll = pair.server.poll_negotiate();
        transcript += pair.io.server_tx_stream.borrow().len();

        if client_poll.is_ready() && server_poll.is_ready() {
            assert!(matches!(client_poll, Poll::Ready(Ok(_))));
            assert!(matches!(server_poll, Poll::Ready(Ok(_))));
            break;
        }
    }
    (transcript, pair.server.actual_protocol_version().unwrap())
}

fn handshake_with_flipped_bit(pair: &mut TestPair, bit: usize) -> Result<(), S2NError> {
    let mut mutated = false;
    let mut transcript_bits = 0;
    let mut poll_count = 0;

    loop {
        poll_count += 1;
        if poll_count > 10 {
            // we consider this as error -> we (correctly) fail to handshake.
            // We might return pending if e.g. an attacker flips a bit on the
            // record header length, making s2n-tls think that more data is coming
            return Err(S2NError::application("multiple poll pending".into()));
        }

        let mut both_ready = true;
        for (peer, buffer) in [
            (&mut pair.client, &pair.io.client_tx_stream),
            (&mut pair.server, &pair.io.server_tx_stream),
        ] {
            let poll = peer.poll_negotiate();
            if let Poll::Ready(Err(e)) = poll {
                return Err(e);
            }

            let written_bits = buffer.borrow().len() * 8;
            if transcript_bits + written_bits > bit && !mutated {
                // the bit index into the current payload
                let record_bit_index = bit - transcript_bits;

                let mut guard = buffer.borrow_mut();
                let buffer = guard.make_contiguous();
                if !tamper_bit(buffer, record_bit_index) {
                    // This bit is in an unprotected region, skip it
                    return Err(S2NError::application(
                        "success: skipping unprotected bit".into(),
                    ));
                }

                mutated = true;
            }
            transcript_bits += written_bits;

            both_ready = both_ready && poll.is_ready();
        }

        if both_ready {
            return Ok(());
        }
    }
}

/// Assert that flipping any single bit in an encrypted record is rejected.
fn assert_all_mutations_rejected(config: &config::Config) {
    // Verify the unmodified record decrypts successfully.
    let (length, _) = negotiation_check(config);

    for bit_index in 0..(length * 8) {
        let mut pair = TestPair::from_config(config);
        let result = handshake_with_flipped_bit(&mut pair, bit_index);
        match result {
            Ok(()) => {
                // Handshake succeeded despite the bit flip
                panic!("bit flip at {bit_index} did not fail");
            }
            Err(_) => {
                // Handshake failed as expected
            }
        }
    }
}

/// Build a config using a self-signed RSA 2048 certificate generated via rcgen.
fn build_config(policy: &Policy) -> Result<config::Config, S2NError> {
    let key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256).unwrap();
    let cert = CertificateParams::default().self_signed(&key_pair).unwrap();

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let mut builder = config::Config::builder();
    builder
        .set_security_policy(policy)?
        .load_pem(cert_pem.as_bytes(), key_pem.as_bytes())?
        .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?
        .with_system_certs(false)?
        .trust_pem(cert_pem.as_bytes())?;
    builder.build()
}

#[test]
fn tls13() {
    required_capability(&[Capability::Tls13], || {
        let config = build_config(&Policy::from_version("default_tls13").unwrap()).unwrap();
        let (length_a, _) = negotiation_check(&config);
        let (length_b, version) = negotiation_check(&config);
        assert_eq!(length_a, length_b);
        assert_eq!(version, Version::TLS13);

        assert_all_mutations_rejected(&config);
    });
}

#[test]
fn tls12() {
    let config = build_config(&Policy::from_version("test_all_tls12").unwrap()).unwrap();

    let (length_a, _) = negotiation_check(&config);
    let (length_b, version) = negotiation_check(&config);
    assert_eq!(length_a, length_b);
    assert_eq!(version, Version::TLS12);

    assert_all_mutations_rejected(&config);
}
