// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{
    config::Config,
    connection::{Connection, ModifiedBuilder},
    enums::PskHmac,
    error::Error,
    psk::{Builder as PskBuilder, Psk},
    testing::LIFOSessionResumption,
};
use s2n_tls_tokio::{EarlyDataStatus, TlsAcceptor, TlsConnector};
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub mod common;

// Session ticket key material for resumption-based tests. Test-only values.
// The key name must be at most S2N_TICKET_KEY_NAME_LEN (16) bytes.
const TICKET_KEY_NAME: &[u8] = b"tokio-ed-key-001";
const TICKET_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

/// Server config that issues session tickets and accepts up to `MAX_EARLY_DATA` bytes of
/// early data on resumed connections (the limit is baked into the issued tickets).
fn resumption_server_config() -> Result<Config, Box<dyn std::error::Error>> {
    let mut builder = common::server_config()?;
    builder
        .add_session_ticket_key(TICKET_KEY_NAME, TICKET_KEY, SystemTime::now())?
        .set_server_max_early_data_size(MAX_EARLY_DATA)?;
    Ok(builder.build()?)
}

/// Client config that stores received session tickets and offers the most recent one on
/// the next connection (one shared `LIFOSessionResumption` handler does both).
fn resumption_client_config() -> Result<Config, Box<dyn std::error::Error>> {
    let resumption = LIFOSessionResumption::default();
    let mut builder = common::client_config()?;
    builder
        .enable_session_tickets(true)?
        .set_session_ticket_callback(resumption.clone())?
        .set_connection_initializer(resumption)?;
    Ok(builder.build()?)
}

const EARLY_DATA: &[u8] = b"hello 0-RTT world";
const MAX_EARLY_DATA: u32 = 4096;
// IANA value for TLS_AES_128_GCM_SHA256, which uses SHA256.
const CIPHER_SUITE: [u8; 2] = [0x13, 0x01];
const PSK_IDENTITY: &[u8] = b"tokio-early-data-identity";

/// Build an external PSK allowing up to `max` bytes of early data.
fn early_data_psk(max: u32) -> Psk {
    let mut builder = PskBuilder::new().unwrap();
    builder.set_identity(PSK_IDENTITY).unwrap();
    builder
        .set_secret(b"a secret that is definitely at least 128 bits long")
        .unwrap();
    builder.set_hmac(PskHmac::SHA256).unwrap();
    builder.configure_early_data(max, CIPHER_SUITE).unwrap();
    builder.build().unwrap()
}

/// A connection modifier that appends an early-data PSK allowing `max` bytes.
fn with_early_data_psk(
    max: u32,
) -> impl Fn(&mut Connection) -> Result<&mut Connection, Error> + Clone {
    move |conn: &mut Connection| {
        conn.append_psk(&early_data_psk(max))?;
        Ok(conn)
    }
}

/// When the server does not allow early data (no early-data PSK), the client's early
/// data is rejected. The handshake still succeeds and the caller can resend the data
/// over the established stream.
#[tokio::test]
async fn early_data_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    // Client offers early data via a PSK, but the server has no matching PSK and
    // therefore falls back to a full handshake, rejecting the early data.
    let client_builder = ModifiedBuilder::new(
        common::client_config()?.build()?,
        with_early_data_psk(MAX_EARLY_DATA),
    );
    let server = TlsAcceptor::new(common::server_config()?.build()?);
    let client = TlsConnector::new(client_builder);

    let (client_result, server_result) = tokio::join!(
        client.connect_with_early_data("localhost", client_stream, EARLY_DATA),
        server.accept(server_stream),
    );

    let (mut client_tls, status) = client_result?;
    let mut server_tls = server_result?;

    // The client requested early data, but the server had no matching PSK and rejected it.
    assert_eq!(status, EarlyDataStatus::Rejected);

    // The handshake still completed successfully, so the caller can send the data
    // over the negotiated stream.
    client_tls.write_all(EARLY_DATA).await?;
    client_tls.flush().await?;
    let mut buf = vec![0; EARLY_DATA.len()];
    server_tls.read_exact(&mut buf).await?;
    assert_eq!(buf, EARLY_DATA);

    Ok(())
}

/// Offering zero-length early data via `connect_with_early_data` is allowed: the send
/// path handles an empty buffer, the handshake completes normally, no early data is
/// actually accepted, and the negotiated stream is usable for application data.
#[tokio::test]
async fn empty_early_data_send() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client_builder = ModifiedBuilder::new(
        common::client_config()?.build()?,
        with_early_data_psk(MAX_EARLY_DATA),
    );
    let server_builder = ModifiedBuilder::new(
        common::server_config()?.build()?,
        with_early_data_psk(MAX_EARLY_DATA),
    );

    let client = TlsConnector::new(client_builder);
    let server = TlsAcceptor::new(server_builder);

    let (client_result, server_result) = tokio::join!(
        client.connect_with_early_data("localhost", client_stream, b""),
        server.accept(server_stream),
    );

    let (mut client_tls, status) = client_result?;
    let mut server_tls = server_result?;

    // `connect_with_early_data` still requests early data even with an empty buffer, so
    // the status reflects the server's decision rather than `NotRequested`. Here the
    // server does not complete the early-data exchange, so the request is `Rejected`.
    assert_eq!(status, EarlyDataStatus::Rejected);

    // The handshake completed and the stream works for ordinary application data.
    const APP_DATA: &[u8] = b"application data after empty early data";
    client_tls.write_all(APP_DATA).await?;
    client_tls.flush().await?;
    let mut buf = vec![0; APP_DATA.len()];
    server_tls.read_exact(&mut buf).await?;
    assert_eq!(buf, APP_DATA);

    Ok(())
}

/// End-to-end accepted early data over TLS 1.3 session resumption (the real 0-RTT use
/// case): a first full handshake issues a session ticket, then the client resumes with it
/// and offers early data that the server accepts. Both sides report `End` and `resumed`,
/// and the server receives the early data exactly once.
#[tokio::test]
async fn early_data_accepted() -> Result<(), Box<dyn std::error::Error>> {
    // Shared configs: the client handler stores/offers tickets across both connections,
    // and the server issues tickets carrying the max early data size.
    let client_config = resumption_client_config()?;
    let server_config = resumption_server_config()?;

    let client = TlsConnector::new(client_config);
    let server = TlsAcceptor::new(server_config);

    // Connection 1: full handshake, no early data. This is where the server issues the
    // session ticket the client will resume with.
    {
        let (server_stream, client_stream) = common::get_streams().await?;
        let (client_result, server_result) = tokio::join!(
            client.connect("localhost", client_stream),
            server.accept(server_stream),
        );
        let mut client_tls = client_result?;
        let mut server_tls = server_result?;

        // TLS 1.3 sends the NewSessionTicket after the handshake, so the client must read
        // once to receive and store it. Exchange a message to ensure it arrives first.
        server_tls.write_all(b"ticket-flush").await?;
        server_tls.flush().await?;
        let mut buf = [0; 12];
        client_tls.read_exact(&mut buf).await?;

        assert!(
            !client_tls.as_ref().resumed(),
            "first handshake is not resumed"
        );
    }

    // Connection 2: resume using the stored ticket and offer early data.
    let (server_stream, client_stream) = common::get_streams().await?;
    let (client_result, server_result) = tokio::join!(
        client.connect_with_early_data("localhost", client_stream, EARLY_DATA),
        server.accept_with_early_data(server_stream),
    );

    let (mut client_tls, client_status) = client_result?;
    let (mut server_tls, early_data) = server_result?;

    // The second connection resumed the session and the early data was accepted.
    assert!(
        client_tls.as_ref().resumed(),
        "second handshake should resume"
    );
    assert!(
        server_tls.as_ref().resumed(),
        "second handshake should resume"
    );
    assert_eq!(client_status, EarlyDataStatus::End);
    assert_eq!(
        server_tls.as_ref().early_data_status()?,
        EarlyDataStatus::End
    );

    // The server received exactly the early data the client sent, once.
    assert_eq!(early_data, EARLY_DATA);

    // The negotiated stream still works normally for post-handshake application data.
    const POST_HANDSHAKE: &[u8] = b"post-handshake data";
    client_tls.write_all(POST_HANDSHAKE).await?;
    client_tls.flush().await?;
    let mut buf = vec![0; POST_HANDSHAKE.len()];
    server_tls.read_exact(&mut buf).await?;
    assert_eq!(buf, POST_HANDSHAKE);

    Ok(())
}

/// The server's `accept_with_early_data` receive path handles a client that offers no
/// early data at all (a plain `connect`): the handshake completes, the returned early
/// data is empty, and the status is not `End`.
#[tokio::test]
async fn accept_with_early_data_none_offered() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client = TlsConnector::new(common::client_config()?.build()?);
    let server_builder = ModifiedBuilder::new(
        common::server_config()?.build()?,
        with_early_data_psk(MAX_EARLY_DATA),
    );
    let server = TlsAcceptor::new(server_builder);

    let (client_result, server_result) = tokio::join!(
        client.connect("localhost", client_stream),
        server.accept_with_early_data(server_stream),
    );

    let _client_tls = client_result?;
    let (server_tls, early_data) = server_result?;

    assert!(early_data.is_empty());
    // The client never requested early data (plain `connect`), so the server reports
    // `NotRequested`.
    assert_eq!(
        server_tls.as_ref().early_data_status()?,
        EarlyDataStatus::NotRequested
    );

    Ok(())
}

/// Accepting early data larger than the receive buffer's initial capacity. The payload
/// spans multiple TLS records, so the server reads it across multiple
/// `poll_recv_early_data` calls and grows its buffer as needed. All bytes must be
/// received intact and in order.
#[tokio::test]
async fn early_data_accepted_large() -> Result<(), Box<dyn std::error::Error>> {
    // 48 KiB of early data with a 64 KiB PSK limit. This exceeds a single TLS record and
    // is larger than typical initial buffer sizing, exercising the multi-read/grow path.
    const MAX: u32 = 64 * 1024;
    let payload: Vec<u8> = (0..48 * 1024).map(|i| (i % 251) as u8).collect();

    let (server_stream, client_stream) = common::get_streams().await?;

    let client_builder =
        ModifiedBuilder::new(common::client_config()?.build()?, with_early_data_psk(MAX));
    let server_builder =
        ModifiedBuilder::new(common::server_config()?.build()?, with_early_data_psk(MAX));

    let client = TlsConnector::new(client_builder);
    let server = TlsAcceptor::new(server_builder);

    let (client_result, server_result) = tokio::join!(
        client.connect_with_early_data("localhost", client_stream, &payload),
        server.accept_with_early_data(server_stream),
    );

    let (_client_tls, client_status) = client_result?;
    let (server_tls, early_data) = server_result?;

    assert_eq!(client_status, EarlyDataStatus::End);
    assert_eq!(
        server_tls.as_ref().early_data_status()?,
        EarlyDataStatus::End
    );
    assert_eq!(early_data.len(), payload.len());
    assert_eq!(early_data, payload);

    Ok(())
}
