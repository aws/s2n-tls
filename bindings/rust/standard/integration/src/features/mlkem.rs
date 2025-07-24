// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use openssl::ssl::{Ssl, SslContextBuilder, SslFiletype, SslMethod};
use s2n_tls::{config::Config, security::DEFAULT_PQ};
use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
use std::{fs, path::Path, pin::Pin};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;

const TEST_PEMS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../tests/pems/");

pub async fn get_streams() -> Result<(TcpStream, TcpStream), tokio::io::Error> {
    let localhost = "127.0.0.1".to_owned();
    let listener = TcpListener::bind(format!("{localhost}:0")).await?;
    let addr = listener.local_addr()?;
    let client_stream = TcpStream::connect(&addr).await?;
    let (server_stream, _) = listener.accept().await?;
    Ok((server_stream, client_stream))
}

#[test_log::test(tokio::test)]
async fn s2n_client_mlkem() -> Result<(), Box<dyn std::error::Error>> {
    let cert_path = format!("{TEST_PEMS_PATH}mlkem/secp384r1.crt");
    let key_path = format!("{TEST_PEMS_PATH}mlkem/secp384r1.priv");

    let (server_stream, client_stream) = get_streams().await?;

    // Setup Openssl 3.5 server restricted to SecP384r1MLKEM1024
    let mut server = {
        let mut builder = SslContextBuilder::new(SslMethod::tls())?;
        builder.set_private_key_file(key_path, SslFiletype::PEM)?;
        builder.set_certificate_chain_file(cert_path.clone())?;
        builder.set_groups_list("SecP384r1MLKEM1024")?;
        let context = builder.build();
        let ssl = Ssl::new(&context)?;
        SslStream::new(ssl, server_stream)?
    };

    // Setup s2n-tls client with default_pq
    let client = {
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_PQ)?;
        config.trust_location(Some(Path::new(&cert_path)), None)?;
        TlsConnector::new(config.build()?)
    };

    let server_pin = Pin::new(&mut server);
    let (_, client_result) = tokio::join!(
        server_pin.accept(),
        client.connect("localhost", client_stream),
    );

    let client = client_result?;
    let conn = client.as_ref();

    let kem_group = conn.kem_group_name().ok_or("No KEM group negotiated")?;
    assert_eq!(
        kem_group, "SecP384r1MLKEM1024",
        "Unexpected KEM group: {:?}",
        kem_group
    );
    Ok(())
}

#[test_log::test(tokio::test)]
async fn s2n_server_mlkem() -> Result<(), Box<dyn std::error::Error>> {
    let cert_path = format!("{TEST_PEMS_PATH}mlkem/secp384r1.crt");
    let key_path = format!("{TEST_PEMS_PATH}mlkem/secp384r1.priv");

    let (server_stream, client_stream) = get_streams().await?;

    // Setup Openssl 3.5 client restricted to SecP384r1MLKEM1024
    let mut client = {
        let mut builder = SslContextBuilder::new(SslMethod::tls())?;
        builder.set_ca_file(Path::new(&cert_path))?;
        builder.set_groups_list("SecP384r1MLKEM1024")?;
        let context = builder.build();
        let ssl = Ssl::new(&context)?;
        SslStream::new(ssl, client_stream)?
    };

    let server = {
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_PQ)?;
        let cert = fs::read(&cert_path)?;
        let key = fs::read(&key_path)?;
        config.load_pem(&cert, &key)?;
        TlsAcceptor::new(config.build()?)
    };

    let client_pin = Pin::new(&mut client);
    let (server_result, _) = tokio::join!(server.accept(server_stream), client_pin.connect(),);

    let server = server_result?;
    let conn = server.as_ref();
    let kem_group = conn.kem_group_name().ok_or("No KEM group negotiated")?;

    assert_eq!(
        kem_group, "SecP384r1MLKEM1024",
        "Unexpected KEM group: {:?}",
        kem_group
    );
    Ok(())
}
