// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::{
    callbacks::VerifyHostNameCallback, config::Config, enums::ClientAuthType,
    security::DEFAULT_TLS13,
};
use s2n_tls_tokio::TlsAcceptor;
use std::{error::Error, fs};
use tokio::{io::AsyncWriteExt, net::TcpListener};

/// NOTE: this certificate, key, and ca are to be used for demonstration purposes only!
const DEFAULT_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../certs/kangaroo-chain.pem");
const DEFAULT_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../certs/kangaroo-key.pem");
const DEFAULT_CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../certs/ca-cert.pem");

/// The name that the server expects to find on trusted client certificates.
const TRUSTED_CLIENT_NAME: &str = "www.wombat.com";

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, requires = "key", default_value_t = String::from(DEFAULT_CERT))]
    cert: String,
    #[clap(short, long, requires = "cert", default_value_t = String::from(DEFAULT_KEY))]
    key: String,
    /// CA used to validate client certificates.
    #[clap(short, long, default_value_t = String::from(DEFAULT_CA))]
    trust: String,
    #[clap(short, long, default_value_t = String::from("127.0.0.1:0"))]
    addr: String,
}

/// Verifies the identity on client certificates.
///
/// When client authentication is used, the server MUST implement a host name
/// verification callback: the default behavior will likely reject all client
/// certificates.
struct TrustedClientName;
impl VerifyHostNameCallback for TrustedClientName {
    fn verify_host_name(&self, host_name: &str) -> bool {
        host_name == TRUSTED_CLIENT_NAME
    }
}

async fn run_server(
    cert_pem: &[u8],
    key_pem: &[u8],
    trust_pem: &[u8],
    addr: &str,
) -> Result<(), Box<dyn Error>> {
    // Set up the configuration for new connections.
    // As with a normal TLS server, you will need a certificate and private key.
    let mut builder = Config::builder();
    builder.set_security_policy(&DEFAULT_TLS13)?;
    builder.load_pem(cert_pem, key_pem)?;

    // Require clients to prove their identity with a client certificate.
    builder.set_client_auth_type(ClientAuthType::Required)?;

    // Client certificates are validated against the server's trust store.
    // Only trust the example CA, not the default system certificates:
    // any certificate signed by a system CA should not be treated as
    // a valid client identity.
    builder.trust_pem(trust_pem)?;
    builder.with_system_certs(false)?;
    builder.set_verify_host_callback(TrustedClientName)?;

    let config = builder.build()?;

    // Create the TlsAcceptor based on the configuration.
    let server = TlsAcceptor::new(config);

    // Bind to an address and listen for connections.
    // ":0" can be used to automatically assign a port.
    let listener = TcpListener::bind(&addr).await?;
    let addr = listener
        .local_addr()
        .map(|x| x.to_string())
        .unwrap_or_else(|_| "UNKNOWN".to_owned());
    println!("Listening on {}", addr);

    loop {
        // Wait for a client to connect.
        let (stream, peer_addr) = listener.accept().await?;
        println!("Connection from {:?}", peer_addr);

        // Spawn a new task to handle the connection.
        // We probably want to spawn the task BEFORE calling TcpAcceptor::accept,
        // because the TLS handshake can be slow.
        let server = server.clone();
        tokio::spawn(async move {
            // The handshake fails if the client can't prove its identity,
            // so unauthorized clients are rejected here.
            let mut tls = match server.accept(stream).await {
                Ok(tls) => tls,
                Err(error) => {
                    println!("Rejected connection from {:?}: {}", peer_addr, error);
                    return Ok(());
                }
            };
            println!("{:#?}", tls);

            // Copy data from the client to stdout
            let mut stdout = tokio::io::stdout();
            tokio::io::copy(&mut tls, &mut stdout).await?;
            tls.shutdown().await?;
            println!("Connection from {:?} closed", peer_addr);

            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let cert_pem = fs::read(args.cert)?;
    let key_pem = fs::read(args.key)?;
    let trust_pem = fs::read(args.trust)?;
    run_server(&cert_pem, &key_pem, &trust_pem, &args.addr).await?;
    Ok(())
}
