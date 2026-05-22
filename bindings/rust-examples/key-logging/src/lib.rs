// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This example shows how to setup key logging for our rust bindings.
//!
//! This builds off the the basic client and server configuration, so be sure to
//! first check out the `tokio-server-client` example if you are generally unfamiliar
//! with s2n-tls APIs.

use s2n_tls::ffi::*;
use std::{
    ffi::{self},
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    sync::{Arc, Mutex},
};

pub type KeyLogHandle = Arc<TlsKeyLogger>;

/// The TlsKeyLogger can be used to log the keys from a TLS session, which can
/// then be used to decrypt the TLS session with a tool like [wireshark](https://wiki.wireshark.org/TLS).
/// This is incredibly useful when attempting to debug failures in TLS connections.
pub struct TlsKeyLogger(Mutex<BufWriter<File>>);

impl TlsKeyLogger {
    /// Use `from_env` when you want to set the path at runtime. The keys will be
    /// written to the path contained in the `SSLKEYLOGFILE` environment variable
    /// ```text
    /// SSLKEYLOGFILE=my_secrets.key ./my_tls_application_binary
    /// ```
    pub fn from_env() -> Option<KeyLogHandle> {
        let path = std::env::var("SSLKEYLOGFILE").ok()?;
        Self::from_path(&path).ok()
    }

    pub fn from_path(path: &str) -> std::io::Result<KeyLogHandle> {
        let file = OpenOptions::new().append(true).create(true).open(path)?;
        let file = BufWriter::new(file);
        let file = Mutex::new(file);
        let keylog = Self(file);
        let keylog = Arc::new(keylog);
        Ok(keylog)
    }

    pub unsafe extern "C" fn callback(
        ctx: *mut ffi::c_void,
        _conn: *mut s2n_connection,
        logline: *mut u8,
        len: usize,
    ) -> ffi::c_int {
        let handle = &mut *(ctx as *mut Self);
        let logline = core::slice::from_raw_parts(logline, len);

        // ignore any errors
        let _ = handle.on_logline(logline);

        0
    }

    fn on_logline(&mut self, logline: &[u8]) -> Option<()> {
        let mut file = self.0.lock().ok()?;
        file.write_all(logline).ok()?;
        file.write_all(b"\n").ok()?;

        // ensure keys are immediately written so tools can use them
        file.flush().ok()?;

        Some(())
    }
}

#[cfg(test)]
mod tests {
    use s2n_tls::{config::Config, security::DEFAULT_TLS13};
    use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::*;

    /// NOTE: these materials are to be used for demonstration purposes only!
    const CA: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../certs/ca-cert.pem"));
    const CHAIN: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../certs/localhost-chain.pem"
    ));
    const KEY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../certs/localhost-key.pem"
    ));
    const SERVER_MESSAGE: &[u8] = b"hello world";

    async fn launch_server() -> anyhow::Result<SocketAddr> {
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.load_pem(CHAIN, KEY)?;
        config.set_max_blinding_delay(0)?;

        let server = TlsAcceptor::new(config.build()?);

        let listener = TcpListener::bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;

        tokio::spawn(async move {
            loop {
                let (stream, _peer_addr) = listener.accept().await.unwrap();

                let server = server.clone();
                tokio::spawn(async move {
                    let mut tls = server.accept(stream).await?;
                    tls.write_all(SERVER_MESSAGE).await?;
                    tls.shutdown().await?;
                    Ok::<(), anyhow::Error>(())
                });
            }
        });

        Ok(addr)
    }

    #[tokio::test]
    async fn client_key_logging() -> anyhow::Result<()> {
        const KEY_PATH: &str = "s2n_client.keys";

        // do some tls stuff
        {
            let key_logger = TlsKeyLogger::from_path(KEY_PATH).unwrap();

            let mut client_config = s2n_tls::config::Builder::new();
            client_config.trust_pem(CA)?;
            client_config.set_security_policy(&DEFAULT_TLS13)?;
            unsafe {
                // The s2n-tls API currently requires a raw C callback and a raw C "context"
                // pointer, although we have plans to improve this in the future:
                // https://github.com/aws/s2n-tls/issues/4805. (Please +1 if interested)
                //
                // The callback is the "extern C" function that we defined for the TlsKeyLogger,
                // and we get the underlying pointer to the KeyLogger to use as the
                // context pointer.
                client_config.set_key_log_callback(
                    Some(TlsKeyLogger::callback),
                    Arc::as_ptr(&key_logger) as *mut _,
                )
            }?;
            let server_addr = launch_server().await?;

            let client = TlsConnector::new(client_config.build()?);
            println!("connecting TCP stream");
            let stream = TcpStream::connect(server_addr).await?;

            let mut tls = client.connect("localhost", stream).await.unwrap();
            let mut buffer = [0; SERVER_MESSAGE.len()];
            tls.read_exact(&mut buffer).await?;
            assert_eq!(buffer, SERVER_MESSAGE);
        }

        // the keys are now available
        {
            let keys = std::fs::read_to_string(KEY_PATH)?;
            assert!(keys.contains("CLIENT_HANDSHAKE_TRAFFIC_SECRET"));
            assert!(keys.contains("SERVER_HANDSHAKE_TRAFFIC_SECRET"));
        }

        // clean up after ourselves
        std::fs::remove_file(KEY_PATH)?;

        Ok(())
    }
}
