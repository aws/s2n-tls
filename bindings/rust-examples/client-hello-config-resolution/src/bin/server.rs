// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{
    callbacks::{ClientHelloCallback, ConnectionFuture},
    security::{Policy, DEFAULT_TLS13},
};
use s2n_tls_tokio::TlsAcceptor;
use std::{collections::HashMap, error::Error, pin::Pin};
use tokio::{io::AsyncWriteExt, net::*};

const PORT: u16 = 1738;

/// Used by the server to resolve the appropriate config
pub struct AnimalConfigResolver {
    // this stores the mapping from sni -> config
    configs: HashMap<String, s2n_tls::config::Config>,
}

impl Default for AnimalConfigResolver {
    fn default() -> Self {
        let mut configs = HashMap::new();
        configs.insert("www.wombat.com".to_owned(), server_config("wombat"));
        configs.insert("www.kangaroo.com".to_owned(), server_config("kangaroo"));
        Self { configs }
    }
}

// Servers that wish to do config resolution in an async manner should consider
// using the ConfigResolver: https://docs.rs/s2n-tls/latest/s2n_tls/callbacks/struct.ConfigResolver.html#
// This is useful if servers need to read from disk or make network calls as part
// of the configuration, and want to avoid blocking the tokio task while doing so.
// An example of this implementation is contained in the "async_load_server".
impl ClientHelloCallback for AnimalConfigResolver {
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
        let config_ref = match self.configs.get(sni) {
            Some(c) => c,
            None => {
                println!("unknown sni: {sni}");
                return Err(s2n_tls::error::Error::application("unknown sni".into()));
            }
        };
        println!("setting connection config associated with {sni}");
        let config = config_ref.clone();
        connection.set_config(config).unwrap();
        // Inform s2n-tls that the server name was used in configuration so that
        // the appropriate extension is sent back to the peer.
        // From RFC 6066, section 3
        // > A server that receives a client hello containing the "server_name"
        // > extension MAY use the information contained in the extension to guide
        // > its selection of an appropriate certificate to return to the client,
        // > and/or other aspects of security policy.  In this event, the server
        // > SHALL include an extension of type "server_name" in the (extended)
        // > server hello.  The "extension_data" field of this extension SHALL be
        // > empty.
        // https://datatracker.ietf.org/doc/html/rfc6066#section-3
        connection.server_name_extension_used();
        // Ok -> the function completed successfully
        // None -> s2n-tls doesn't need to poll this to completion
        Ok(None)
    }
}

fn server_config(animal: &str) -> s2n_tls::config::Config {
    let cert_path = format!("{}/certs/{}-chain.pem", env!("CARGO_MANIFEST_DIR"), animal);
    let key_path = format!("{}/certs/{}-key.pem", env!("CARGO_MANIFEST_DIR"), animal);
    let cert = std::fs::read(cert_path).unwrap();
    let key = std::fs::read(key_path).unwrap();
    let mut config = s2n_tls::config::Builder::new();

    // we can set different policies for different configs. "20190214" doesn't
    // support TLS 1.3, so any customer requesting www.wombat.com won't be able
    // to negotiate TLS 1.3
    let security_policy = match animal {
        "wombat" => Policy::from_version("20190214").unwrap(),
        _ => DEFAULT_TLS13,
    };
    config.set_security_policy(&security_policy).unwrap();
    config.load_pem(&cert, &key).unwrap();
    config.build().unwrap()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let resolver = AnimalConfigResolver::default();

    // this is the initial config that "receives" the connection. Since we error
    // out on an unrecognized SNI, the only important setting on this config is
    // the client hello callback that sets the config used for the rest of the
    // connection.
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
