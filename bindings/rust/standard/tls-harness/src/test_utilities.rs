// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    TlsConnPair, TlsConnection,
    harness::{TlsConfigBuilder, TlsConfigBuilderPair},
};

/// Perform a simple server-auth handshake.
pub fn handshake<C, B>()
where
    C: TlsConnection,
    B: TlsConfigBuilder<Config = C::Config>,
{
    let mut conn_pair: TlsConnPair<C, C> = {
        let config_pair: TlsConfigBuilderPair<B, B> = TlsConfigBuilderPair::default();
        config_pair.connection_pair()
    };
    conn_pair.handshake().unwrap();
    conn_pair.round_trip_transfer(&mut [0]).unwrap();
    conn_pair.shutdown().unwrap();
}

/// Round-trip-transfer 1 MB of data.
pub fn transfer<C, B>()
where
    C: TlsConnection,
    B: TlsConfigBuilder<Config = C::Config>,
{
    let mut conn_pair: TlsConnPair<C, C> = {
        let config_pair: TlsConfigBuilderPair<B, B> = TlsConfigBuilderPair::default();
        config_pair.connection_pair()
    };
    conn_pair.handshake().unwrap();
    let mut data = [0; 1_000_000];
    conn_pair.round_trip_transfer(&mut data).unwrap();
    conn_pair.shutdown().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use brass_aphid_wire_decryption::decryption::key_manager::KeyManager;
    use brass_aphid_wire_messages::iana;
    use openssl::ssl::SslContextBuilder;

    use crate::{
        TlsConnPair,
        cohort::{OpenSslConnection, S2NConnection},
    };

    /// make sure that the brass-aphid-wire integration is able to correctly decrypt
    /// TLS 1.3 conversations
    #[test]
    fn tls13_decryption() {
        let key_manager = KeyManager::new();
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs
                .server
                .set_security_policy(&s2n_tls::security::DEFAULT)
                .unwrap();
            key_manager.enable_s2n_logging(&mut configs.server);
            configs.client.set_groups_list("x448:secp256r1").unwrap();
            configs.connection_pair()
        };
        pair.io.enable_recording();
        pair.io.enable_decryption(key_manager.clone());

        pair.handshake().unwrap();
        pair.shutdown().unwrap();

        let transcript = pair.io.decrypter.borrow();
        let transcript = transcript.as_ref().unwrap().transcript();
        let ch = transcript.client_hellos().first().unwrap().clone();
        let client_key_shares = ch.key_share().unwrap();
        let client_supported_groups = ch.supported_groups().unwrap();

        // openssl sends the most preferred group as a key share
        assert_eq!(client_key_shares, vec![iana::constants::x448]);
        assert_eq!(
            client_supported_groups,
            vec![iana::constants::x448, iana::constants::secp256r1]
        );

        // s2n-tls selects secp256r1
        let sh = transcript.server_hello();
        let selected_group = sh.selected_group().unwrap().unwrap();
        assert_eq!(selected_group, iana::constants::secp256r1);

        // there was an HRR
        assert!(transcript.hello_retry_request().is_some());
    }
}
