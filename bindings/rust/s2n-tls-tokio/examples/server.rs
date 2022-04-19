// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::raw::{config::Config, error::Error, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsAcceptor;
use std::fs;
use tokio::net::TcpListener;

/// NOTE: this certificate and key are to be used for demonstration purposes only!
const DEFAULT_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/cert.pem");
const DEFAULT_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/key.pem");

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, requires = "key", default_value_t = String::from(DEFAULT_CERT))]
    cert: String,
    #[clap(short, long, requires = "cert", default_value_t = String::from(DEFAULT_KEY))]
    key: String,
    #[clap(short, long, default_value_t = String::from("127.0.0.1:0"))]
    addr: String,
}

async fn run_server(cert_pem: &[u8], key_pem: &[u8], addr: &String) -> Result<(), Error> {
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.load_pem(&cert_pem, &key_pem)?;
    let server = TlsAcceptor::new(config.build()?);

    let listener = TcpListener::bind(&addr)
        .await
        .expect("Failed to bind listener");
    let addr = listener
        .local_addr()
        .map(|x| x.to_string())
        .unwrap_or("UNKNOWN".to_owned());
    println!("Listening on {}", addr);

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .expect("Failed to accept connection");
        println!("Connection from {:?}", peer_addr);
        server.accept(stream).await?;
        // TODO: echo
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();
    let cert_pem = fs::read(args.cert).expect("Failed to load cert");
    let key_pem = fs::read(args.key).expect("Failed to load key");
    run_server(&cert_pem, &key_pem, &args.addr).await?;
    Ok(())
}
