// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! An mTLS client that presents a client certificate to the server. The server
//! validates it against an asynchronously fetched CRL (see `server.rs`).

use s2n_tls::{enums::ClientAuthType, security::DEFAULT_TLS13};
use std::error::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::*,
};

const PORT: u16 = 1739;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let certs = format!("{}/../certs", env!("CARGO_MANIFEST_DIR"));

    let mut config = s2n_tls::config::Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    // Trust the CA so we can verify the server's certificate.
    config.trust_pem(&std::fs::read(format!("{certs}/ca-cert.pem"))?)?;
    // Present our own client certificate for mutual TLS.
    config.set_client_auth_type(ClientAuthType::Required)?;
    config.load_pem(
        &std::fs::read(format!("{certs}/wombat-chain.pem"))?,
        &std::fs::read(format!("{certs}/wombat-key.pem"))?,
    )?;

    let client = s2n_tls_tokio::TlsConnector::new(config.build()?);
    let stream = TcpStream::connect(("127.0.0.1", PORT)).await?;

    // In TLS 1.3, the client finishes its side of the handshake before the
    // server validates the client certificate. A rejection therefore surfaces
    // on the client either as a handshake error here, or (more commonly) as an
    // error on the first read below, when the server closes the connection.
    let mut tls = match client.connect("localhost", stream).await {
        Ok(tls) => tls,
        Err(e) => {
            println!("handshake failed (client certificate rejected): {e}");
            return Ok(());
        }
    };

    let mut response = String::new();
    match tls.read_to_string(&mut response).await {
        // The server only sends a message once it accepts the certificate, so
        // an empty response means the server closed the connection after
        // rejecting us.
        Ok(_) if !response.is_empty() => println!("server said: {response}"),
        Ok(_) => println!("client certificate rejected: server closed the connection"),
        Err(e) => println!("client certificate rejected: {e}"),
    }
    let _ = tls.shutdown().await;
    Ok(())
}
