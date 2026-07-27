// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests confirming ClientHello retrieval after a Hello Retry Request.
//!
//! After an HRR, `client_hello()` returns the *second* client hello, while
//! `initial_client_hello()` returns the *first* one sent before the HRR.
//!
//! See: https://github.com/aws/s2n-tls/issues/5961

use std::sync::LazyLock;

use brass_aphid_wire_decryption::decryption::key_manager::KeyManager;
use brass_aphid_wire_messages::{codec::DecodeValue, iana, protocol::ClientHello};
use openssl::ssl::SslContextBuilder;
use s2n_tls::security::Policy;
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair,
};

use crate::capability_check::{required_capability, Capability};

/// strongly preferred groups -> [secp384r1]
static STRONGLY_PREFERRED_GROUPS: LazyLock<Policy> =
    LazyLock::new(|| Policy::from_version("20251117").unwrap());

/// After a Hello Retry Request, s2n-tls exposes both client hellos:
/// - `client_hello()` returns the second (most recent) client hello.
/// - `initial_client_hello()` returns the first client hello — which contains
///   the original key share that triggered the HRR.
///
/// This test:
/// 1. Forces an HRR by having the client offer secp256r1 while the server
///    strongly prefers secp384r1.
/// 2. Captures both client hellos from the wire.
/// 3. Confirms the first client hello has secp256r1, the second has secp384r1.
/// 4. Gets the raw message bytes from both of s2n-tls's stored client hellos,
///    parses them with brass-aphid, and confirms the current client hello has
///    the second key share (secp384r1) and the initial client hello has the
///    first key share (secp256r1).
#[test]
fn both_client_hellos_available_after_hrr() {
    required_capability(&[Capability::Tls13], || {
        let key_manager = KeyManager::new();
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs
                .server
                .set_security_policy(&STRONGLY_PREFERRED_GROUPS)
                .unwrap();
            key_manager.enable_s2n_logging(&mut configs.server);
            configs
                .client
                .set_groups_list("secp256r1:secp384r1")
                .unwrap();
            configs.connection_pair()
        };
        pair.io.enable_recording();
        pair.io.enable_decryption(key_manager.clone());

        pair.handshake().unwrap();
        pair.shutdown().unwrap();

        // --- Wire-level: confirm HRR occurred with two distinct client hellos ---

        let decrypted_stream = pair.io.decrypter.borrow();
        let transcript = decrypted_stream.as_ref().unwrap().transcript();

        assert!(transcript.hello_retry_request().is_some());

        let client_hellos = transcript.client_hellos();
        assert_eq!(client_hellos.len(), 2);

        let first_ch_key_shares = client_hellos[0].key_share().unwrap();
        assert_eq!(first_ch_key_shares, vec![iana::constants::secp256r1]);

        let second_ch_key_shares = client_hellos[1].key_share().unwrap();
        assert_eq!(second_ch_key_shares, vec![iana::constants::secp384r1]);

        // --- s2n-tls API: the current client hello is the second one ---

        let current = pair.server.connection().client_hello().unwrap();
        let current_raw = current.raw_message().unwrap();
        let (current_parsed, _) = ClientHello::decode_from(&current_raw).unwrap();
        assert_eq!(
            current_parsed.key_share().unwrap(),
            vec![iana::constants::secp384r1]
        );

        // --- s2n-tls API: the initial client hello is the first one ---

        let initial = pair
            .server
            .connection()
            .initial_client_hello()
            .expect("initial client hello should be available after an HRR");
        let initial_raw = initial.raw_message().unwrap();
        let (initial_parsed, _) = ClientHello::decode_from(&initial_raw).unwrap();
        assert_eq!(
            initial_parsed.key_share().unwrap(),
            vec![iana::constants::secp256r1]
        );
    });
}

/// Without a Hello Retry Request, only a single client hello is sent, so
/// `initial_client_hello()` returns the same message as `client_hello()`.
#[test]
fn initial_client_hello_matches_current_without_hrr() {
    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
        let mut configs =
            TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
        configs
            .server
            .set_security_policy(&STRONGLY_PREFERRED_GROUPS)
            .unwrap();
        // The client offers the server's preferred group directly, so no
        // HelloRetryRequest is needed.
        configs.client.set_groups_list("secp384r1").unwrap();
        configs.connection_pair()
    };

    pair.handshake().unwrap();
    pair.shutdown().unwrap();

    // A single client hello was received, so the initial and current client
    // hellos are the same message.
    let current_raw = pair
        .server
        .connection()
        .client_hello()
        .unwrap()
        .raw_message()
        .unwrap();
    let initial_raw = pair
        .server
        .connection()
        .initial_client_hello()
        .unwrap()
        .raw_message()
        .unwrap();
    assert_eq!(current_raw, initial_raw);
}
