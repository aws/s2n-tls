// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use futures::join;
use s2n_tls::raw::{config::Config, security::DEFAULT_TLS13};
use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
use tokio::net::{TcpListener, TcpStream};

pub static CERT_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/certs/cert.pem"
));
pub static KEY_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/certs/key.pem"
));
async fn get_streams(addr: &str) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(addr).await.unwrap();
    let client_stream = TcpStream::connect(addr).await.unwrap();
    let (server_stream, _) = listener.accept().await.unwrap();
    (client_stream, server_stream)
}

async fn run_client(stream: TcpStream) {
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13).unwrap();
    config.trust_pem(CERT_PEM).unwrap();
    unsafe {
        config.disable_x509_verification().unwrap();
    }

    let client = TlsConnector::new(config.build().unwrap());
    client.connect("localhost", stream).await.unwrap();
    println!("Client completed handshake");
}

async fn run_server(stream: TcpStream) {
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13).unwrap();
    config.load_pem(CERT_PEM, KEY_PEM).unwrap();

    let server = TlsAcceptor::new(config.build().unwrap());
    server.accept(stream).await.unwrap();
    println!("Server completed handshake");
}

#[tokio::main]
async fn main() {
    let (client_stream, server_stream) = get_streams(&"127.0.0.1:4433").await;

    join!(run_client(client_stream), run_server(server_stream));
}
