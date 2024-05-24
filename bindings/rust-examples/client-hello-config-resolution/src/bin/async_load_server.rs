// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{
    callbacks::{ClientHelloCallback, ConfigResolver, ConnectionFuture},
    config::Config,
    security::{Policy, DEFAULT_TLS13},
};
use s2n_tls_tokio::TlsAcceptor;
use std::{error::Error, future::Future, pin::Pin};
use tokio::{io::AsyncWriteExt, net::*, try_join};

const PORT: u16 = 1738;

#[derive(Clone)]
pub struct AsyncAnimalConfigResolver {
    // the directory that contains the relevant certs
    cert_directory: String,
}

struct SpecificAnimalResolver {
    cert_directory: String,
    animal: String,
}

impl AsyncAnimalConfigResolver {
    fn new(cert_directory: String) -> Self {
        AsyncAnimalConfigResolver { cert_directory }
    }

    // This method will lookup the appropriate certificates and read them from disk
    // in an async manner which won't block the tokio task.
    //
    // Note that this method consumes `self`. A ConfigResolver can be constructed
    // from a future that returns `Result<Config, s2n_tls::error::Error>`, with
    // the main additional requirements that the future is `'static`. This generally
    // means that it can't have any  interior references.
    //
    // If this method took in `&self`, then
    // ```
    // let config_resolver = ConfigResolver::new(self.server_config(animal));
    // ```
    // wouldn't compile because the compiler would complain that `&self` doesn't
    // live long enough.
    async fn server_config(
        self,
        animal: String,
    ) -> Result<s2n_tls::config::Config, s2n_tls::error::Error> {
        let cert_path = format!("{}/{}-chain.pem", self.cert_directory, animal);
        let key_path = format!("{}/{}-key.pem", self.cert_directory, animal);
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

        let async_resolver_clone = self.clone();
        let config_resolver = ConfigResolver::new(async_resolver_clone.server_config(animal));
        Ok(Some(Box::pin(config_resolver)))
    }
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
