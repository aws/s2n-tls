// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::raw::{config::Config, error::Error, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsConnector;
use std::fs;
use tokio::net::TcpStream;

const DEFAULT_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/cert.pem");

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, default_value_t = String::from(DEFAULT_CERT))]
    trust: String,
    addr: String,
}

async fn run_client(trust_pem: &[u8], addr: &String) -> Result<(), Error> {
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.trust_pem(trust_pem)?;
    let client = TlsConnector::new(config.build()?);

    let stream = TcpStream::connect(addr).await.expect("Failed to connect");
    client.connect("localhost", stream).await?;
    // TODO: echo
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();
    let trust_pem = fs::read(args.trust).expect("Failed to load cert");
    run_client(&trust_pem, &args.addr).await?;
    Ok(())
}
