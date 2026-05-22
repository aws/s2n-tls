// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{
    callbacks::{ClientHelloCallback, ConfigResolver, ConnectionFuture},
    security::{Policy, DEFAULT_TLS13},
};
use s2n_tls_tokio::TlsAcceptor;
use std::{error::Error, pin::Pin};
use tokio::{io::AsyncWriteExt, net::*, try_join};

const PORT: u16 = 1738;

#[derive(Clone)]
pub struct AsyncAnimalConfigResolver {
    // the directory that contains the relevant certs
    cert_directory: String,
}

impl AsyncAnimalConfigResolver {
    fn new(cert_directory: String) -> Self {
        AsyncAnimalConfigResolver { cert_directory }
    }
}

impl ClientHelloCallback for AsyncAnimalConfigResolver {
    fn on_client_hello(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        let sni = match connection.server_name() {
            Some(sni) => sni,
            None => {
                println!("connection contained no SNI");
                return Err(s2n_tls::error::Error::application("no sni".into()));
            }
        };

        // simple, limited logic to parse "animal" from "www.animal.com".
        let mut tokens = sni.split('.');
        tokens.next(); // "www"
        let animal = match tokens.next() {
            Some(animal) => animal.to_owned(), // "animal"
            None => {
                println!("unable to parse sni");
                return Err(s2n_tls::error::Error::application(
                    format!("unable to parse sni: {}", sni).into(),
                ));
            }
        };

        let config_future = server_config(animal, self.cert_directory.clone());
        let config_resolver = ConfigResolver::new(config_future);
        connection.server_name_extension_used();
        Ok(Some(Box::pin(config_resolver)))
    }
}

// This method will lookup the appropriate certificates and read them from disk
// in an async manner which won't block the tokio task.
//
// Note that this method takes `String` instead of `&str` like the synchronous
// version in server.rs. ConfigResolver requires a future that is `'static`.
async fn server_config(
    animal: String,
    cert_directory: String,
) -> Result<s2n_tls::config::Config, s2n_tls::error::Error> {
    println!("asynchronously setting connection config associated with {animal}");

    let cert_path = format!("{}/{}-chain.pem", cert_directory, animal);
    let key_path = format!("{}/{}-key.pem", cert_directory, animal);
    // we asynchronously read the cert chain and key from disk
    let (cert, key) = try_join!(tokio::fs::read(cert_path), tokio::fs::read(key_path))
        // we map any IO errors to the s2n-tls Error type, as required by the ConfigResolver bounds.
        .map_err(|io_error| s2n_tls::error::Error::application(Box::new(io_error)))?;

    let mut config = s2n_tls::config::Builder::new();
    // we can set different policies for different configs. "20190214" doesn't
    // support TLS 1.3, so any customer requesting www.wombat.com won't be able
    // to negotiate TLS 1.3
    let security_policy = match animal.as_str() {
        "wombat" => Policy::from_version("20190214")?,
        _ => DEFAULT_TLS13,
    };
    config.set_security_policy(&security_policy)?;
    config.load_pem(&cert, &key)?;
    config.build()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cert_directory = format!("{}/certs", env!("CARGO_MANIFEST_DIR"));
    let resolver = AsyncAnimalConfigResolver::new(cert_directory);
    let mut initial_config = s2n_tls::config::Builder::new();
    initial_config.set_client_hello_callback(resolver)?;

    let server = TlsAcceptor::new(initial_config.build()?);

    let listener = TcpListener::bind(&format!("0.0.0.0:{PORT}")).await?;
    loop {
        let server = server.clone();
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            // handshake with the client
            let handshake = server.accept(stream).await;
            let mut tls = match handshake {
                Ok(tls) => tls,
                Err(e) => {
                    println!("error during handshake: {:?}", e);
                    return Ok(());
                }
            };

            let connection = tls.as_ref();
            let offered_sni = connection.server_name().unwrap();
            let _ = tls
                .write(format!("Hello, you are speaking to {offered_sni}").as_bytes())
                .await?;
            tls.shutdown().await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }
}
