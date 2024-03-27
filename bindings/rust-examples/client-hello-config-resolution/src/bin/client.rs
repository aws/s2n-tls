// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::security::DEFAULT_TLS13;

use std::error::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::*,
};

const PORT: u16 = 1738;

#[derive(Debug, Parser)]
struct Cli {
    /// value to specify for the SNI
    sni: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let mut config = s2n_tls::config::Config::builder();
    let ca: Vec<u8> = std::fs::read(env!("CARGO_MANIFEST_DIR").to_owned() + "/certs/ca-cert.pem")?;
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.trust_pem(&ca)?;

    let client = s2n_tls_tokio::TlsConnector::new(config.build()?);
    let stream = TcpStream::connect(("127.0.0.1", PORT)).await?;
    // request a TLS connection on the TCP stream while setting the sni
    let mut tls = match client.connect(&args.sni, stream).await {
        Ok(tls) => tls,
        Err(e) => {
            println!("error during handshake: {:?}", e);
            return Ok(());
        }
    };
    println!("{:#?}", tls);

    let mut server_response = String::new();
    tls.read_to_string(&mut server_response).await?;
    println!("The server said {server_response}");
    tls.shutdown().await?;

    Ok(())
}
