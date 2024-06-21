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

/// hyper clients use a connector to send and receive HTTP requests over an underlying IO stream. By
/// default, hyper provides `hyper_util::client::legacy::connect::HttpConnector` for this purpose,
/// which sends and receives requests over TCP.
///
/// The `HttpsConnector` struct wraps an HTTP connector, and uses it to negotiate TLS when the HTTPS
/// scheme is in use. The `HttpsConnector` can be provided to the
/// `hyper_util::client::legacy::Client` builder as follows:
/// ```
/// use hyper_util::{
///     client::legacy::Client,
///     rt::TokioExecutor,
/// };
/// use s2n_tls_hyper::connector::HttpsConnector;
/// use s2n_tls::config::Config;
/// use bytes::Bytes;
/// use http_body_util::Empty;
///
/// let connector = HttpsConnector::builder(Config::default()).build();
/// let client: Client<_, Empty<Bytes>> =
///     Client::builder(TokioExecutor::new()).build(connector);
/// ```
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
    /// `conn_builder` will be used to produce the s2n-tls Connections used for negotiating HTTPS,
    /// which can be an `s2n_tls::config::Config` or other `s2n_tls::connection::Builder`.
    ///
    /// This builder is created using the default hyper `HttpConnector`. To use an existing HTTP
    /// connector, use `HttpsConnector::builder_with_http()`.
    pub fn builder(conn_builder: B) -> Builder<HttpConnector, B> {
        let mut http = HttpConnector::new();

        // By default, the `HttpConnector` only allows the HTTP URI scheme to be used. To negotiate
        // HTTP over TLS via the HTTPS scheme, `enforce_http` must be disabled.
        http.enforce_http(false);

        Builder::new(http, conn_builder)
    }
}

impl<T, B> HttpsConnector<T, B>
where
    B: connection::Builder,
    <B as connection::Builder>::Output: Unpin,
{
    /// Creates a new `Builder` used to create an `HttpsConnector`.
    ///
    /// `conn_builder` will be used to produce the s2n-tls Connections used for negotiating HTTPS,
    /// which can be an `s2n_tls::config::Config` or other `s2n_tls::connection::Builder`.
    ///
    /// This API allows a `Builder` to be constructed with an existing HTTP connector, as follows:
    /// ```
    /// use s2n_tls_hyper::connector::HttpsConnector;
    /// use s2n_tls::config::Config;
    /// use hyper_util::client::legacy::connect::HttpConnector;
    ///
    /// let mut http = HttpConnector::new();
    ///
    /// // Ensure that the HTTP connector permits the HTTPS scheme.
    /// http.enforce_http(false);
    ///
    /// let builder = HttpsConnector::builder_with_http(http, Config::default());
    /// ```
    ///
    /// `HttpsConnector::builder()` can be used to create a new HTTP connector automatically.
    pub fn builder_with_http(http: T, conn_builder: B) -> Builder<T, B> {
        Builder::new(http, conn_builder)
    }
}

// hyper connectors MUST implement `hyper_util::client::legacy::connect::Connect`, which is an alias
// for the `tower_service::Service` trait where `Service` is implemented for `http::uri::Uri`, and
// `Service::Response` implements traits for compatibility with hyper:
// https://docs.rs/hyper-util/latest/hyper_util/client/legacy/connect/trait.Connect.html
//
// The hyper compatibility traits for `Service::Response` are implemented in `MaybeHttpsStream`.
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
        // Currently, the only supported stream type is TLS. If the application attempts to
        // negotiate HTTP over plain TCP, return an error.
        if req.scheme() == Some(&http::uri::Scheme::HTTP) {
            return Box::pin(async move { Err(UnsupportedScheme.into()) });
        }

        let builder = self.conn_builder.clone();
        let host = req.host().unwrap_or("").to_owned();
        let call = self.http.call(req);
        Box::pin(async move {
            // `HttpsConnector` wraps an HTTP connector that also implements `Service<Uri>`.
            // `call()` is invoked on the wrapped connector to get the underlying hyper TCP stream,
            // which is converted into a tokio-compatible stream with `hyper_util::rt::TokioIo`.
            let tcp = call.await.map_err(Into::into)?;
            let tcp = TokioIo::new(tcp);

            let connector = TlsConnector::new(builder);
            let tls = connector.connect(&host, tcp).await?;

            Ok(MaybeHttpsStream::Https(TokioIo::new(tls)))
        })
    }
}

/// The `Builder` struct configures and produces a new `HttpsConnector`. A Builder can be retrieved
/// with `HttpsConnector::builder()`, as follows:
/// ```
/// use s2n_tls_hyper::connector::HttpsConnector;
/// use s2n_tls::config::Config;
///
/// let builder = HttpsConnector::builder(Config::default());
/// ```
pub struct Builder<T, B>
where
    B: connection::Builder,
    <B as connection::Builder>::Output: Unpin,
{
    http: T,
    conn_builder: B,
}

impl<T, B> Builder<T, B>
where
    B: connection::Builder,
    <B as connection::Builder>::Output: Unpin,
{
    /// Creates a new `Builder` used to create an `HttpsConnector`.
    pub fn new(http: T, conn_builder: B) -> Self {
        Self { http, conn_builder }
    }

    /// Creates a new `HttpsConnector` from the specified builder configuration.
    pub fn build(self) -> HttpsConnector<T, B> {
        HttpsConnector {
            http: self.http,
            conn_builder: self.conn_builder,
        }
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
    use http_body_util::Empty;
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};
    use std::{error::Error, str::FromStr};

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
