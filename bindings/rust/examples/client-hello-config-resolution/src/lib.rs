use s2n_tls::{
    callbacks::{ClientHelloCallback, ConnectionFuture},
    enums::Version,
    security::{Policy, DEFAULT, DEFAULT_TLS13},
};
use s2n_tls_tokio::TlsAcceptor;
use std::{
    collections::HashMap,
    error::Error,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use turmoil::net::*;

const PORT: u16 = 1738;

/// Used by the server to resolve the appropriate config
pub struct AnimalConfigResolver {
    // this stores the mapping from sni -> config
    configs: HashMap<String, s2n_tls::config::Config>,
}

impl AnimalConfigResolver {
    pub fn new() -> Self {
        let mut configs = HashMap::new();
        configs.insert("www.wombat.com".to_owned(), server_config("wombat"));
        configs.insert("www.kangaroo.com".to_owned(), server_config("kangaroo"));
        Self { configs }
    }
}

impl ClientHelloCallback for AnimalConfigResolver {
    fn on_client_hello(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        let sni = match connection.server_name() {
            Some(sni) => sni,
            None => {
                return Err(s2n_tls::error::Error::application(
                    "connection contained no sni".into(),
                ))
            }
        };
        let config_ref = match self.configs.get(sni) {
            Some(c) => c,
            None => {
                return Err(s2n_tls::error::Error::application(
                    format!("unexpected SNI {sni}").into(),
                ))
            }
        };
        println!("client hello callback: setting connection config associated with {sni}");
        let config = config_ref.clone();
        connection.set_config(config).unwrap();
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
    // to negoatiate TLS 1.3
    let security_policy = match animal {
        "wombat" => Policy::from_version("20190214").unwrap(),
        _ => DEFAULT_TLS13,
    };
    config.set_security_policy(&security_policy).unwrap();
    config.load_pem(&cert, &key).unwrap();
    config.build().unwrap()
}

pub fn client_config() -> s2n_tls::config::Config {
    let mut config = s2n_tls::config::Config::builder();
    let ca: Vec<u8> =
        std::fs::read(env!("CARGO_MANIFEST_DIR").to_owned() + "/certs/ca-cert.pem").unwrap();
    config.set_security_policy(&DEFAULT_TLS13).unwrap();
    config.trust_pem(&ca).unwrap();
    config.build().unwrap()
}

#[test]
fn scenario() -> turmoil::Result {
    // turmoil is a network simulator, so we can simulate running a single and
    // two servers without having to spin up multiple processes or wait for
    // real time to elapse
    let mut sim = turmoil::Builder::new().build();

    sim.host("server", || async {
        let resolver = AnimalConfigResolver::new();

        let mut initial_config = s2n_tls::config::Builder::new();
        initial_config.set_client_hello_callback(resolver)?;

        let server = TlsAcceptor::new(initial_config.build()?);

        let listener = TcpListener::bind((IpAddr::from(Ipv4Addr::UNSPECIFIED), PORT)).await?;
        loop {
            let server = server.clone();
            let (stream, _) = listener.accept().await?;
            tokio::spawn(async move {
                // handshake with the client
                let mut tls = server
                    .accept(stream)
                    .await
                    .expect("server failure to negoatiate");
                println!("{:#?}", tls);

                let connection = tls.as_ref();
                let offered_sni = connection.server_name().unwrap();
                tls.write(format!("Hello, you are speaking to {offered_sni}").as_bytes())
                    .await?;
                tls.shutdown().await?;
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            });
        }
    });

    sim.client("wombat-client", async {
        let mut config = s2n_tls::config::Config::builder();
        let ca: Vec<u8> =
            std::fs::read(env!("CARGO_MANIFEST_DIR").to_owned() + "/certs/ca-cert.pem")?;
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.trust_pem(&ca)?;

        // Create the TlsConnector based on the configuration.
        let client = s2n_tls_tokio::TlsConnector::new(config.build()?);
        let stream = TcpStream::connect(("server", PORT)).await?;
        // request a TLS connection on the TCP stream while setting the sni to
        // www.wombat.com
        let mut tls = client.connect("www.wombat.com", stream).await?;

        // when using the "wombat" SNI, the maximum allowed protocol version is TLS1.2 because
        // of the different configs that are served.
        assert_eq!(
            tls.as_ref().actual_protocol_version().unwrap(),
            Version::TLS12
        );
        let mut server_response = String::new();
        tls.read_to_string(&mut server_response).await?;
        println!("The server said {server_response}");
        tls.shutdown().await?;
        Ok(())
    });

    sim.client("kangaroo-client", async {
        let mut config = s2n_tls::config::Config::builder();
        let ca: Vec<u8> =
            std::fs::read(env!("CARGO_MANIFEST_DIR").to_owned() + "/certs/ca-cert.pem")?;
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.trust_pem(&ca)?;

        let client = s2n_tls_tokio::TlsConnector::new(config.build()?);
        let stream = TcpStream::connect(("server", PORT)).await?;
        // request a TLS connection on the TCP stream while setting the sni to
        // www.kangaroo.com
        let mut tls = client.connect("www.kangaroo.com", stream).await?;
        assert_eq!(
            tls.as_ref().actual_protocol_version().unwrap(),
            Version::TLS13
        );
        let mut server_response = String::new();
        tls.read_to_string(&mut server_response).await?;
        println!("The server said {server_response}");
        tls.shutdown().await?;

        Ok(())
    });

    sim.run()
}
