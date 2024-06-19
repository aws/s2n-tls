// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::stream::MaybeHttpsStream;
use http::uri::Uri;
use hyper::rt::{Read, Write};
use hyper_util::{
    client::legacy::connect::{Connection, HttpConnector},
    rt::TokioIo,
};
use s2n_tls::{config::Config, connection};
use s2n_tls_tokio::TlsConnector;
use std::{
    fmt,
    fmt::{Debug, Formatter},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower_service::Service;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct HttpsConnector<T, B = Config>
where
    B: connection::Builder,
    <B as connection::Builder>::Output: Unpin,
{
    http: T,
    conn_builder: B,
}

impl<B> HttpsConnector<HttpConnector, B>
where
    B: connection::Builder,
    <B as connection::Builder>::Output: Unpin,
{
    /// Creates a new `Builder` used to create an `HttpsConnector`.
    ///
    /// This builder is created using the default hyper `HttpConnector`. To use a custom HTTP
    /// connector, use `HttpsConnector::builder_with_http()`.
    pub fn builder(conn_builder: B) -> Builder<HttpConnector, B> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        Builder::new(Self { http, conn_builder })
    }
}

impl<T, B> HttpsConnector<T, B>
where
    B: connection::Builder,
    <B as connection::Builder>::Output: Unpin,
{
    /// Creates a new `Builder` used to create an `HttpsConnector`.
    pub fn builder_with_http(http: T, conn_builder: B) -> Builder<T, B> {
        Builder::new(Self { http, conn_builder })
    }
}

impl<T, B> Service<Uri> for HttpsConnector<T, B>
where
    T: Service<Uri>,
    T::Response: Read + Write + Connection + Unpin + Send + 'static,
    T::Future: Send + 'static,
    T::Error: Into<BoxError>,
    B: connection::Builder + Send + Sync + 'static,
    <B as connection::Builder>::Output: Unpin + Send,
{
    type Response = MaybeHttpsStream<T::Response, B>;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = Result<MaybeHttpsStream<T::Response, B>, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.http.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        if req.scheme() == Some(&http::uri::Scheme::HTTP) {
            return Box::pin(async move { Err(UnsupportedScheme.into()) });
        }

        let builder = self.conn_builder.clone();
        let host = req.host().unwrap_or("").to_owned();
        let call = self.http.call(req);
        Box::pin(async move {
            let tcp = call.await.map_err(Into::into)?;
            let tcp = TokioIo::new(tcp);

            let connector = TlsConnector::new(builder);
            let tls = connector.connect(&host, tcp).await?;

            Ok(MaybeHttpsStream::Https(TokioIo::new(tls)))
        })
    }
}

pub struct Builder<T, B>
where
    B: connection::Builder,
    <B as connection::Builder>::Output: Unpin,
{
    connector: HttpsConnector<T, B>,
}

impl<T, B> Builder<T, B>
where
    B: connection::Builder,
    <B as connection::Builder>::Output: Unpin,
{
    pub fn new(connector: HttpsConnector<T, B>) -> Self {
        Self { connector }
    }

    pub fn build(self) -> HttpsConnector<T, B> {
        self.connector
    }
}

#[derive(Debug)]
struct UnsupportedScheme;

impl fmt::Display for UnsupportedScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("The provided URI scheme is not supported")
    }
}

impl std::error::Error for UnsupportedScheme {}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::status;
    use http_body_util::{BodyExt, Empty};
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};
    use std::{error::Error, str::FromStr};

    #[tokio::test]
    async fn test_get_request() -> Result<(), BoxError> {
        let connector = HttpsConnector::builder(Config::default()).build();
        let client: Client<_, Empty<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let uri = Uri::from_str("https://www.amazon.com")?;
        let response = client.get(uri).await?;
        assert_eq!(response.status(), status::StatusCode::OK);

        let body = response.into_body().collect().await?.to_bytes();
        assert!(!body.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_unsecure_http() -> Result<(), BoxError> {
        let connector = HttpsConnector::builder(Config::default()).build();
        let client: Client<_, Empty<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let uri = Uri::from_str("http://www.amazon.com")?;
        let error = client.get(uri).await.unwrap_err();

        // Ensure that an UnsupportedScheme error is returned when HTTP over TCP is attempted.
        let _ = error
            .source()
            .unwrap()
            .downcast_ref::<UnsupportedScheme>()
            .unwrap();

        Ok(())
    }
}
