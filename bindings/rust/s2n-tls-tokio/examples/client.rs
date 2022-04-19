// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::raw::{config::Config, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsConnector;
use std::{error::Error, fs};
use tokio::net::TcpStream;

/// NOTE: this certificate is to be used for demonstration purposes only!
const DEFAULT_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/cert.pem");

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, default_value_t = String::from(DEFAULT_CERT))]
    trust: String,
    addr: String,
}

async fn run_client(trust_pem: &[u8], addr: &str) -> Result<(), Box<dyn Error>> {
    // Set up the configuration for new connections.
    // Minimally you will need a trust store.
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.trust_pem(trust_pem)?;

    // Create the TlsConnector based on the configuration.
    let client = TlsConnector::new(config.build()?);

    // Connect to the server.
    let stream = TcpStream::connect(addr).await?;
    client.connect("localhost", stream).await?;

    // TODO: echo

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let trust_pem = fs::read(args.trust)?;
    run_client(&trust_pem, &args.addr).await?;
    Ok(())
}
