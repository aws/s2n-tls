// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test confirming that after a Hello Retry Request, `client_hello()` returns
//! the *second* client hello — the first one is lost.
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

/// After a Hello Retry Request, s2n-tls only exposes the second client hello
/// via `s2n_connection_get_client_hello`. The first client hello — which
/// contains the original key share that triggered the HRR — is lost.
///
/// This test:
/// 1. Forces an HRR by having the client offer secp256r1 while the server
///    strongly prefers secp384r1.
/// 2. Captures both client hellos from the wire.
/// 3. Confirms the first client hello has secp256r1, the second has secp384r1.
/// 4. Gets the raw message bytes from s2n-tls's stored client hello, parses
///    them with brass-aphid, and confirms the key share matches the second
///    wire client hello (secp384r1), not the first (secp256r1).
#[test]
fn first_client_hello_not_available_after_hrr() {
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

        assert!(transcript.hello_retry_request().is_some(),);

        let client_hellos = transcript.client_hellos();
        assert_eq!(client_hellos.len(), 2);

        let first_ch_key_shares = client_hellos[0].key_share().unwrap();
        assert_eq!(first_ch_key_shares, vec![iana::constants::secp256r1]);

        let second_ch_key_shares = client_hellos[1].key_share().unwrap();
        assert_eq!(second_ch_key_shares, vec![iana::constants::secp384r1]);

        // --- s2n-tls API: parse the stored client hello and compare key shares ---

        let s2n_client_hello = pair.server.connection().client_hello().unwrap();

        let raw = s2n_client_hello.raw_message().unwrap();
        let (parsed, _) = ClientHello::decode_from(&raw).unwrap();

        let stored_key_shares = parsed.key_share().unwrap();

        assert_eq!(stored_key_shares, vec![iana::constants::secp384r1]);
    });
}
