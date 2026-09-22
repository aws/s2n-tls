// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use foreign_types::ForeignTypeRef;
use openssl::ssl::{SslContextBuilder, SslFiletype, SslVersion};
use s2n_tls::{
    security,
    testing::{CertKeyPair, InsecureAcceptAllCertificatesHandler},
};
use std::{
    io::{Read, Write},
    task::Poll,
};
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    openssl_extension::{SSL_key_update, SSL_KEY_UPDATE_REQUESTED},
    TlsConnPair,
};

// Check that an s2n-tls split connection can continue to read and write data after
// reading a key update requested message. s2n-tls itself never sends key update requested
// messages, so we use Openssl as a peer to generate the key update request.
#[test]
fn peer_requested_key_update_after_split() -> Result<(), Box<dyn std::error::Error>> {
    const SERVER_DATA: &[u8] = b"beep boop";
    const CLIENT_DATA: &[u8] = b"boop beep";

    let pair = key_update_test_pair()?;
    let TlsConnPair {
        client,
        server,
        io: _,
    } = pair;
    let S2NConnection {
        connection: client,
        io: _,
    } = client;
    // Split the client into independent read and write halves.
    let (mut read, mut write) = client.split();

    let OpenSslConnection {
        connection: mut server,
    } = server;
    let ssl_ptr = server.ssl().as_ptr();
    let rc = unsafe { SSL_key_update(ssl_ptr, SSL_KEY_UPDATE_REQUESTED) };
    assert_eq!(rc, 1, "SSL_key_update should succeed");

    // This write will flush the key update message before sending SERVER_DATA.
    server.write_all(SERVER_DATA)?;

    // Decrypting SERVER_DATA correctly proves the read half handled the peer's key update.
    let mut recv_buffer = vec![0; SERVER_DATA.len()];
    let expected_output = SERVER_DATA.to_vec();
    assert!(matches!(
        read.poll_recv(&mut recv_buffer),
        Poll::Ready(Ok(..))
    ));
    assert_eq!(recv_buffer, expected_output);

    // The write half sends data. Because openssl requested a key update,
    // s2n-tls sends its own KeyUpdate record (updating its sending key) ahead
    // of the application data.
    assert!(write.poll_send(CLIENT_DATA).is_ready());

    // openssl reads the data, processing the s2n-tls KeyUpdate record and
    // updating its receiving key. Decrypting CLIENT_DATA correctly proves the
    // write half's key update was accepted by the peer.
    let mut server_recv = vec![0; CLIENT_DATA.len()];
    server.read_exact(&mut server_recv)?;
    assert_eq!(server_recv, CLIENT_DATA);

    let counts = read.key_update_counts()?;
    assert_eq!(counts.recv_key_updates, 1, "read half updated the recv key");
    assert_eq!(
        counts.send_key_updates, 1,
        "write half updated the send key"
    );

    Ok(())
}

fn key_update_test_pair(
) -> Result<TlsConnPair<S2NConnection, OpenSslConnection>, Box<dyn std::error::Error>> {
    let certs = CertKeyPair::from_path(
        "permutations/rsae_pkcs_4096_sha384/",
        "server-chain",
        "server-key",
        "ca-cert",
    );

    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = {
        let mut configs =
            TlsConfigBuilderPair::<s2n_tls::config::Builder, SslContextBuilder>::default();
        // Setup s2n-tls client with default_pq
        configs
            .client
            .set_security_policy(&security::DEFAULT_TLS13)
            .unwrap();
        configs.client.trust_pem(certs.ca_cert())?;
        configs
            .client
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
        configs.client.with_system_certs(false)?;

        // Build the openssl server, restricted to TLS1.3.
        configs
            .server
            .set_min_proto_version(Some(SslVersion::TLS1_3))?;
        configs
            .server
            .set_certificate_chain_file(certs.cert_path())?;
        configs
            .server
            .set_private_key_file(certs.key_path(), SslFiletype::PEM)?;

        configs.connection_pair()
    };

    pair.handshake().unwrap();

    Ok(pair)
}
