// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::security::DEFAULT_TLS13;
use s2n_tls_tokio::TlsAcceptor;
use std::{error::Error, time::SystemTime};
use tokio::{io::AsyncWriteExt, net::TcpListener};

const KEY: [u8; 16] = [0; 16];
const KEY_NAME: [u8; 3] = [1, 3, 4];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cert_path = format!("{}/certs/test-cert.pem", env!("CARGO_MANIFEST_DIR"));
    let key_path = format!("{}/certs/test-key.pem", env!("CARGO_MANIFEST_DIR"));
    let cert = std::fs::read(cert_path).unwrap();
    let key = std::fs::read(key_path).unwrap();

    let mut config = s2n_tls::config::Builder::new();
    config.set_security_policy(&DEFAULT_TLS13).unwrap();
    config
        .add_session_ticket_key(&KEY_NAME, &KEY, SystemTime::now())
        .unwrap();
    config.load_pem(&cert, &key).unwrap();
    let config = config.build()?;
    let server = TlsAcceptor::new(config);

    let listener = TcpListener::bind("0.0.0.0:9000").await?;
    loop {
        let server = server.clone();
        let (stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            let handshake = server.accept(stream).await;
            let mut tls = match handshake {
                Ok(tls) => tls,
                Err(e) => {
                    println!("error during handshake: {e}");
                    return Ok(());
                }
            };

            let _ = tls.write("hello from server.".as_bytes()).await?;
            tls.shutdown().await?;

            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }
}
