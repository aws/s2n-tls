// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validate the send buffering behavior configured by
//! `s2n_config_set_send_buffer_size`.
//!
//! Note that there are lots of asserts who

use std::sync::LazyLock;

use openssl::ssl::SslContextBuilder;
use s2n_tls::{config::Builder, enums::Version, security::Policy};
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair,
};

use crate::utilities::capability_check::{required_capability, Capability};

/// The smallest send buffer s2n-tls allows, `S2N_MIN_SEND_BUFFER_SIZE`.
const MIN_SEND_BUFFER: usize = 1_034;
/// A buffer large enough to batch several max-size records per write.
const LARGE_SEND_BUFFER: usize = 64 * 1024;

const APP_DATA_SIZE: usize = 256 * 1_024;

const RECORD_HEADER_SIZE: usize = 5;

static TLS13_POLICY: LazyLock<Policy> = LazyLock::new(|| Policy::from_version("20251015").unwrap());
static TLS12_POLICY: LazyLock<Policy> = LazyLock::new(|| Policy::from_version("20140601").unwrap());

/// `S2N_TLS_MAXIMUM_FRAGMENT_LENGTH`: the largest plaintext fragment (2^14).
const MAX_FRAGMENT_LEN: u16 = 16_384;
/// `S2N_SMALL_FRAGMENT_LENGTH`: `prefer_low_latency` targets a single network
/// frame: `1500 - 20 (IP) - 20 (TCP) - 20 (TCP options) - 5 (record header)`.
const SMALL_FRAGMENT_LEN: u16 = 1500 - 20 - 20 - 20 - RECORD_HEADER_SIZE as u16;

/// The cipher suites negotiated by the policies under test.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq)]
enum CipherSuite {
    /// Negotiated by the TLS 1.3 policy. AES-128-GCM: 16 byte tag, fully-implicit
    /// nonce (RFC 8446 5.3) so no explicit per-record IV on the wire.
    TLS_AES_128_GCM_SHA256,
    /// Negotiated by the TLS 1.2 policy. AES-128-CBC (16 byte block, 16 byte
    /// explicit IV in TLS 1.1+) with an HMAC-SHA256 (32 byte) digest.
    TLS_RSA_WITH_AES_128_CBC_SHA_256,
}

/// Compute the on-wire record length field that s2n-tls will produce, by walking
/// through the same calculation as `s2n_record_write.c`. This lets tests derive
/// the expected record length instead of hardcoding it.
///
/// `send_buffer` is the optional `s2n_config_set_send_buffer_size` override, and
/// `fragment` is the plaintext fragment length s2n targets (e.g. the max, or the
/// smaller `prefer_low_latency` size).
fn record_model(
    protocol: Version,
    cipher_suite: CipherSuite,
    fragment: u16,
    send_buffer: usize,
) -> u16 {
    /// `S2N_TLS13_ENCRYPTION_OVERHEAD_SIZE`: the maximum AEAD expansion s2n
    /// pessimistically reserves per RFC 8446 5.2, even though real ciphers use less.
    const TLS13_MAX_ENCRYPTION_OVERHEAD: u16 = 255;
    /// `S2N_TLS12_ENCRYPTION_OVERHEAD_SIZE`: the padding/expansion s2n pessimistically
    /// reserves for a TLS 1.2 record.
    const TLS12_MAX_ENCRYPTION_OVERHEAD: u16 = 1024;

    /// `S2N_TLS_CONTENT_TYPE_LENGTH`: the inner content type byte on TLS 1.3 records.
    const CONTENT_TYPE_LEN: u16 = 1;

    assert!(fragment <= MAX_FRAGMENT_LEN);
    let mut plaintext_payload = fragment;

    // Step 1: if a custom send buffer is configured, s2n checks it against aggressively
    // pessimistic assumptions about record sizing, instead of using the actual
    // negotiated parameters.
    //
    let rfc_allowed_record_size = {
        let pessimistic_encryption_overhead = if protocol == Version::TLS13 {
            CONTENT_TYPE_LEN + TLS13_MAX_ENCRYPTION_OVERHEAD
        } else {
            TLS12_MAX_ENCRYPTION_OVERHEAD
        };
        (plaintext_payload + pessimistic_encryption_overhead + RECORD_HEADER_SIZE as u16) as usize
    };

    if send_buffer < rfc_allowed_record_size {
        // decrease the plaintext payload, because it's possible that it wouldn't
        // fit in the buffer when encrypted
        let overflow = rfc_allowed_record_size - send_buffer;
        plaintext_payload -= overflow as u16;
    }

    // Step 2: the per-record overhead added on top of the plaintext fragment.
    let cipher_overhead = match cipher_suite {
        // TLS 1.3 AEAD overhead is just the tag (implicit IV, no explicit bytes).
        CipherSuite::TLS_AES_128_GCM_SHA256 => 16,
        // CBC overhead is the HMAC digest (32) + 1 padding-length byte + explicit IV (16).
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA_256 => {
            // HMAC digest (32) + 1 padding-length byte + explicit IV (16)
            let static_overhead = 32 + 1 + 16;
            let required_padding = {
                // block size is 16
                let partial_block = (plaintext_payload + static_overhead) % 16;
                if partial_block != 0 {
                    16 - partial_block
                } else {
                    0
                }
            };
            static_overhead + required_padding
        }
    };

    let mut final_record_size = plaintext_payload + cipher_overhead;

    // Step 3: TLS 1.3 protected records carry one extra inner content type byte.
    if protocol == Version::TLS13 {
        final_record_size += CONTENT_TYPE_LEN;
    }

    final_record_size
}

/// Transfer [`APP_DATA_SIZE`] using the configured IO behavior.
///
/// Internal assertions
/// - client and server behaviors are identical
/// - data was transferred successfully
/// - record and write sizes vectors are nonempty
fn io_behavior(s2n_policy: &Policy, send_buffer_size: Option<usize>, fragment: u16) -> IoBehavior {
    // Apply the common s2n-tls config: a TLS 1.2 policy (so record behavior is
    // consistent regardless of the peer) and the optional send buffer override.
    let configure_s2n = |builder: &mut Builder| {
        // builder.set_security_policy(&TLS12_POLICY).unwrap();
        if let Some(size) = send_buffer_size {
            builder.set_send_buffer_size(size as u32).unwrap();
            builder.set_security_policy(s2n_policy).unwrap();
        }
    };

    // Map the requested fragment length back to the coarse setting that produces
    // it. The default (no call) already targets the max fragment.
    let apply_fragmentation = |conn: &mut s2n_tls::connection::Connection| match fragment {
        MAX_FRAGMENT_LEN => {}
        SMALL_FRAGMENT_LEN => {
            conn.prefer_low_latency().unwrap();
        }
        other => panic!("s2n-tls cannot be configured to target a {other} byte fragment"),
    };

    let server_behavior = {
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configure_s2n(&mut configs.server);
            configs.connection_pair()
        };

        apply_fragmentation(pair.server.connection_mut());
        pair.handshake().unwrap();

        // Only record application data, not the handshake.
        pair.io.enable_recording();
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();

        // we assert on the negotiated cipher, which we have made assumptions
        // about in `record_model`
        if *s2n_policy == *TLS13_POLICY {
            assert_eq!(
                pair.server.connection().cipher_suite().unwrap(),
                "TLS_AES_128_GCM_SHA256"
            );
        } else if *s2n_policy == *TLS12_POLICY {
            assert_eq!(
                pair.server.connection().cipher_suite().unwrap(),
                "AES128-SHA256"
            );
        } else {
            panic!("unsupported policy, you need to update the cipher table")
        }

        let transfer = IoBehavior {
            write_sizes: pair.io.server_write_sizes(),
            record_sizes: pair.io.server_record_sizes(),
        };

        pair.shutdown().unwrap();
        transfer
    };

    let client_behavior = {
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<s2n_tls::config::Builder, SslContextBuilder>::default();
            configure_s2n(&mut configs.client);
            configs.connection_pair()
        };

        apply_fragmentation(pair.client.connection_mut());
        pair.handshake().unwrap();

        // Only record application data, not the handshake.
        pair.io.enable_recording();
        pair.round_trip_assert(APP_DATA_SIZE).unwrap();

        let transfer = IoBehavior {
            write_sizes: pair.io.client_write_sizes(),
            record_sizes: pair.io.client_record_sizes(),
        };

        pair.shutdown().unwrap();
        transfer
    };

    assert_eq!(server_behavior, client_behavior);
    assert!(!client_behavior.record_sizes.is_empty());
    assert!(!client_behavior.write_sizes.is_empty());
    client_behavior
}

#[derive(PartialEq)]
struct IoBehavior {
    /// The byte length of each transport-level write made.
    write_sizes: Vec<usize>,
    /// The size of each TLS record payload written (excludes record header).
    record_sizes: Vec<u16>,
}

impl std::fmt::Debug for IoBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoBehavior")
            .field("write_sizes (len)", &self.write_sizes.len())
            .field("write_sizes[0]", &self.write_sizes[0])
            .field("record_sizes(len)", &self.record_sizes.len())
            .field("record_sizes[0]", &self.record_sizes[0])
            .finish()
    }
}

impl IoBehavior {
    /// Check that all (full) writes are `expected_write` len
    pub fn writes_equal(&self, expected_write: usize) -> bool {
        assert!(self.write_sizes.len() > 1);
        self.write_sizes
            .iter()
            .take(self.write_sizes.len() - 1)
            .all(|write| *write == expected_write)
    }

    /// Check that all (full) records are `expected_record` len
    pub fn records_equal(&self, expected_record: u16) -> bool {
        assert!(self.record_sizes.len() > 1);
        self.record_sizes
            .iter()
            .take(self.record_sizes.len() - 1)
            .all(|write| *write == expected_record)
    }

    fn expected_write_payload(buffer_size: usize, record_size: u16) -> usize {
        // plus record header overhead
        let record_write = (record_size + 5) as usize;

        let record_capacity = buffer_size / record_write;
        record_capacity * record_write
    }
}

#[test]
fn minimum_send_buffer_size() {
    // we can do things with the minimum send buffer
    let behavior = io_behavior(&TLS12_POLICY, Some(MIN_SEND_BUFFER), MAX_FRAGMENT_LEN);
    assert!(behavior
        .write_sizes
        .iter()
        .all(|size| *size as u32 <= MIN_SEND_BUFFER as u32));

    // try the size below the minimum, and it should fail
    let mut builder = Builder::new();
    assert!(builder
        .set_send_buffer_size((MIN_SEND_BUFFER - 1) as u32)
        .is_err());
}

/// in the default case, s2n-tls will issue one write per record.
#[test]
fn default_one_record_one_write() {
    required_capability(&[Capability::Tls13], || {
        let default = io_behavior(&TLS13_POLICY, None, MAX_FRAGMENT_LEN);
        assert_eq!(default.write_sizes.len(), default.record_sizes.len());
    });
}

/// a large enough send buffer reduces the number of writes
#[test]
fn send_buffer_reduces_writes() {
    required_capability(&[Capability::Tls13], || {
        let behavior = io_behavior(&TLS13_POLICY, Some(LARGE_SEND_BUFFER), MAX_FRAGMENT_LEN);
        assert!(behavior.write_sizes.len() < behavior.record_sizes.len());

        let expected_record = record_model(
            Version::TLS13,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            MAX_FRAGMENT_LEN,
            LARGE_SEND_BUFFER,
        );
        assert_eq!(expected_record, 16_401);
        let expected_write = IoBehavior::expected_write_payload(LARGE_SEND_BUFFER, expected_record);
        assert_eq!(expected_write, 49_218);

        assert!(behavior.writes_equal(expected_write));
        assert!(behavior.records_equal(expected_record));
    });

    // TLS 1.2
    {
        let behavior = io_behavior(&TLS12_POLICY, Some(LARGE_SEND_BUFFER), MAX_FRAGMENT_LEN);
        assert!(behavior.write_sizes.len() < behavior.record_sizes.len());

        let expected_record = record_model(
            Version::TLS12,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA_256,
            MAX_FRAGMENT_LEN,
            LARGE_SEND_BUFFER,
        );
        assert_eq!(expected_record, 16_448);
        let expected_write = IoBehavior::expected_write_payload(LARGE_SEND_BUFFER, expected_record);
        assert_eq!(expected_write, 49_359);

        assert!(behavior.writes_equal(expected_write));
        assert!(behavior.records_equal(expected_record));
    }
}

/// record size can be configured separately from the send buffer size.
#[test]
fn buffered_send_with_small_records() {
    required_capability(&[Capability::Tls13], || {
        let behavior = io_behavior(&TLS13_POLICY, Some(LARGE_SEND_BUFFER), SMALL_FRAGMENT_LEN);
        assert!(behavior.write_sizes.len() < behavior.record_sizes.len());

        let expected_record = record_model(
            Version::TLS13,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            SMALL_FRAGMENT_LEN,
            LARGE_SEND_BUFFER,
        );
        assert_eq!(expected_record, 1_452);
        let expected_write = IoBehavior::expected_write_payload(LARGE_SEND_BUFFER, expected_record);
        assert_eq!(expected_write, 64_108);

        assert!(behavior.writes_equal(expected_write));
        assert!(behavior.records_equal(expected_record));
    });

    // TLS 1.2
    {
        let behavior = io_behavior(&TLS12_POLICY, Some(LARGE_SEND_BUFFER), SMALL_FRAGMENT_LEN);
        assert!(behavior.write_sizes.len() < behavior.record_sizes.len());

        let expected_record = record_model(
            Version::TLS12,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA_256,
            SMALL_FRAGMENT_LEN,
            LARGE_SEND_BUFFER,
        );
        assert_eq!(expected_record, 1_488);
        let expected_write = IoBehavior::expected_write_payload(LARGE_SEND_BUFFER, expected_record);
        assert_eq!(expected_write, 64_199);

        assert!(behavior.writes_equal(expected_write));
        assert!(behavior.records_equal(expected_record));
    }
}

/// If the send buffer is smaller than the configured record size, then s2n-tls
/// will resort to sending small records that fit in the send buffer.
///
/// This record sizing is currently very pessimistic.
/// https://github.com/aws/s2n-tls/issues/6059
#[test]
fn small_buffer_override_large_records() {
    required_capability(&[Capability::Tls13], || {
        let behavior = io_behavior(&TLS13_POLICY, Some(MIN_SEND_BUFFER), MAX_FRAGMENT_LEN);
        assert_eq!(behavior.write_sizes.len(), behavior.record_sizes.len());

        let expected_record = record_model(
            Version::TLS13,
            CipherSuite::TLS_AES_128_GCM_SHA256,
            MAX_FRAGMENT_LEN,
            MIN_SEND_BUFFER,
        );
        assert_eq!(expected_record, 790);
        assert!(behavior.records_equal(expected_record));
        assert!(behavior.writes_equal(expected_record as usize + RECORD_HEADER_SIZE));
    });

    // TLS 1.2
    {
        let behavior = io_behavior(&TLS12_POLICY, Some(MIN_SEND_BUFFER), MAX_FRAGMENT_LEN);
        assert_eq!(behavior.write_sizes.len(), behavior.record_sizes.len());

        let expected_record = record_model(
            Version::TLS12,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA_256,
            MAX_FRAGMENT_LEN,
            MIN_SEND_BUFFER,
        );
        assert_eq!(expected_record, 64);
        assert!(behavior.records_equal(expected_record));
        assert!(behavior.writes_equal(expected_record as usize + RECORD_HEADER_SIZE));
    }
}
