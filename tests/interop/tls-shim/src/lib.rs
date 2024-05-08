// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This lint warns that async functions in trait are especially likely to cause
// unexpected breaking changes because of the type inference on the future bounds.
// We are not concerned about breaking API changes since this is an internal crate,
// and the ergonomic benefits of "async fn" significantly outweigh the stability
// concerns.
//
// However in cases where the additional "async" syntax isn't useful, we prefer
// "impl Future" syntax for the more readable compiler errors that it provides.
#![allow(async_fn_in_trait)]

use std::{error::Error, fmt::Debug};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use common::{InteropTest, CLIENT_GREETING, LARGE_DATA_DOWNLOAD_GB, SERVER_RESPONSE};

pub mod s2n_tls_shim;

const ONE_MB: usize = 1_000_000;
const ONE_GB: usize = 1_000_000_000;

/// The ServerTLS trait allows for shared code between s2n-tls, rustls,
/// and openssl. All of these TLS implementations have relatively similar API shapes
/// which this trait attempts to abstract over.
pub trait ServerTLS<T> {
    type Config;
    type Acceptor: Clone + Send + 'static;
    // the Stream is generic to allow for Turmoil test usage
    type Stream: Send + AsyncRead + AsyncWrite + Debug + Unpin;

    fn get_server_config(test: InteropTest) -> Result<Option<Self::Config>, Box<dyn Error>>;

    fn acceptor(config: Self::Config) -> Self::Acceptor;

    fn accept(
        server: &Self::Acceptor,
        transport_stream: T,
    ) -> impl std::future::Future<Output = Result<Self::Stream, Box<dyn Error + Send + Sync>>> + Send;

    /// `handle_server_connection` provides generic "handle connection" functionality.
    /// It will automatically implement correct application behavior for tests that
    /// don't require any implementation specific apis.
    async fn handle_server_connection(
        test: InteropTest,
        mut stream: Self::Stream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        tracing::info!("Executing the {:?} scenario", test);
        match test {
            InteropTest::Handshake => {
                // no application data exchange in the handshake case
            }
            InteropTest::RequestResponse | InteropTest::MTLSRequestResponse => {
                let mut client_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
                stream.read_exact(&mut client_greeting_buffer).await?;
                assert_eq!(client_greeting_buffer, CLIENT_GREETING.as_bytes());

                stream.write_all(SERVER_RESPONSE.as_bytes()).await?;
            }
            InteropTest::LargeDataDownload => {
                let mut client_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
                stream.read_exact(&mut client_greeting_buffer).await?;
                assert_eq!(client_greeting_buffer, CLIENT_GREETING.as_bytes());

                let mut data_buffer = vec![0; ONE_MB];
                // for each GB
                for i in 0..LARGE_DATA_DOWNLOAD_GB {
                    if i % 10 == 0 {
                        tracing::info!("GB sent: {}", i);
                    }
                    data_buffer[0] = (i % u8::MAX as u64) as u8;
                    for _ in 0..(ONE_GB / ONE_MB) {
                        stream.write_all(&data_buffer).await?;
                    }
                }
            }
            InteropTest::LargeDataDownloadWithFrequentKeyUpdates => {
                Self::handle_large_data_download_with_frequent_key_updates(&mut stream).await?;
            }
            _ => panic!("Internal Framework Error"),
        }

        tracing::info!("waiting for the client to close");
        let wait_close = stream.read(&mut [0]).await?;
        assert_eq!(wait_close, 0);

        tracing::info!("closing the server side of connection");
        stream.shutdown().await?;
        Ok(())
    }

    /// If server supports the "large_data_download_forced_key_update" scenario,
    /// it should implement this method. The method should *not* handle the
    /// shutdown of the stream. It should only handle the writing of application
    /// messages and the sending of the key updates.
    async fn handle_large_data_download_with_frequent_key_updates(
        _stream: &mut Self::Stream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        Err("unimplemented".into())
    }
}

pub trait ClientTLS<T> {
    type Config;
    type Connector: Clone + Send + 'static;
    type Stream: Send + AsyncRead + AsyncWrite + Debug + Unpin;

    fn get_client_config(test: InteropTest) -> Result<Option<Self::Config>, Box<dyn Error>>;

    fn connector(config: Self::Config) -> Self::Connector;

    fn connect(
        client: &Self::Connector,
        transport_stream: T,
    ) -> impl std::future::Future<Output = Result<Self::Stream, Box<dyn Error + Send + Sync>>> + Send;

    async fn handle_client_connection(
        test: InteropTest,
        mut stream: Self::Stream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        tracing::info!("executing the {:?} scenario", test);
        match test {
            InteropTest::Handshake => { /* no data exchange in the handshake case */ }
            InteropTest::RequestResponse | InteropTest::MTLSRequestResponse => {
                stream.write_all(CLIENT_GREETING.as_bytes()).await?;

                let mut server_response_buffer = vec![0; SERVER_RESPONSE.as_bytes().len()];
                stream.read_exact(&mut server_response_buffer).await?;
                assert_eq!(server_response_buffer, SERVER_RESPONSE.as_bytes());
            }
            InteropTest::LargeDataDownload
            | InteropTest::LargeDataDownloadWithFrequentKeyUpdates => {
                stream.write_all(CLIENT_GREETING.as_bytes()).await?;

                let mut recv_buffer = vec![0; ONE_MB];
                for i in 0..LARGE_DATA_DOWNLOAD_GB {
                    let tag = (i % u8::MAX as u64) as u8;
                    for _ in 0..(ONE_GB / ONE_MB) {
                        stream.read_exact(&mut recv_buffer).await?;
                        assert_eq!(recv_buffer[0], tag);
                    }
                }
            }
            _ => panic!("internal error, unrecognized client test {:?}", test),
        }
        tracing::info!("shutting down the client side of the connection");
        stream.shutdown().await?;

        // wait for the server to shutdown it's side of the connection, which
        // will return a 0 byte read
        tracing::info!("waiting for the server to shut down");
        let shutdown_wait = stream.read(&mut [0]).await?;
        assert_eq!(0, shutdown_wait);

        Ok(())
    }
}
