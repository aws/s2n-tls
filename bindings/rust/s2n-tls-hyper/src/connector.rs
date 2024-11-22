// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{error::Error, stream::MaybeHttpsStream};
use http::uri::Uri;
use hyper::rt::{Read, Write};
use hyper_util::{
    client::legacy::connect::{Connection, HttpConnector},
    rt::TokioIo,
};
use s2n_tls::{config::Config, connection};
use s2n_tls_tokio::TlsConnector;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower_service::Service;

/// hyper-compatible connector used to negotiate HTTPS.
///
/// hyper clients use a connector to send and receive HTTP requests over an underlying IO stream. By
/// default, hyper provides `hyper_util::client::legacy::connect::HttpConnector` for this purpose,
/// which sends and receives requests over TCP. The `HttpsConnector` struct wraps an HTTP connector,
/// and uses it to negotiate TLS when the HTTPS scheme is in use.
#[derive(Clone)]
pub struct HttpsConnector<Http, Builder = Config> {
    http: Http,
    conn_builder: Builder,
}

impl<Builder> HttpsConnector<HttpConnector, Builder>
where
    Builder: connection::Builder,
    <Builder as connection::Builder>::Output: Unpin,
{
    /// Creates a new `HttpsConnector`.
    ///
    /// `conn_builder` will be used to produce the s2n-tls Connections used for negotiating HTTPS,
    /// which can be an `s2n_tls::config::Config` or other `s2n_tls::connection::Builder`.
    ///
    /// This API creates an `HttpsConnector` using the default hyper `HttpConnector`. To use an
    /// existing HTTP connector, use `HttpsConnector::new_with_http()`.
    ///
    /// Note that the HttpsConnector will automatically attempt to negotiate HTTP/2 by overriding
    /// the ALPN extension. Any ALPN values configured on `conn_builder` with APIs like
    /// `s2n_tls::config::Builder::set_application_protocol_preference()` will be ignored.
    pub fn new(conn_builder: Builder) -> HttpsConnector<HttpConnector, Builder> {
        let mut http = HttpConnector::new();

        // By default, the `HttpConnector` only allows the HTTP URI scheme to be used. To negotiate
        // HTTP over TLS via the HTTPS scheme, `enforce_http` must be disabled.
        http.enforce_http(false);

        Self { http, conn_builder }
    }
}

impl<Http, Builder> HttpsConnector<Http, Builder>
where
    Builder: connection::Builder,
    <Builder as connection::Builder>::Output: Unpin,
{
    /// Creates a new `HttpsConnector`.
    ///
    /// `conn_builder` will be used to produce the s2n-tls Connections used for negotiating HTTPS,
    /// which can be an `s2n_tls::config::Config` or other `s2n_tls::connection::Builder`.
    ///
    /// This API allows an `HttpsConnector` to be constructed with an existing HTTP connector, as follows:
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
    /// let connector = HttpsConnector::new_with_http(http, Config::default());
    /// ```
    ///
    /// `HttpsConnector::new()` can be used to create the HTTP connector automatically.
    ///
    /// Note that the HttpsConnector will automatically attempt to negotiate HTTP/2 by overriding
    /// the ALPN extension. Any ALPN values configured on `conn_builder` with APIs like
    /// `s2n_tls::config::Builder::set_application_protocol_preference()` will be ignored.
    pub fn new_with_http(http: Http, conn_builder: Builder) -> HttpsConnector<Http, Builder> {
        Self { http, conn_builder }
    }
}

// hyper connectors MUST implement `hyper_util::client::legacy::connect::Connect`, which is an alias
// for the `tower_service::Service` trait where `Service` is implemented for `http::uri::Uri`, and
// `Service::Response` implements traits for compatibility with hyper:
// https://docs.rs/hyper-util/latest/hyper_util/client/legacy/connect/trait.Connect.html
//
// The hyper compatibility traits for `Service::Response` are implemented in `MaybeHttpsStream`.
impl<Http, Builder> Service<Uri> for HttpsConnector<Http, Builder>
where
    Http: Service<Uri>,
    Http::Response: Read + Write + Connection + Unpin + Send + 'static,
    Http::Future: Send + 'static,
    Http::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    Builder: connection::Builder + Send + Sync + 'static,
    <Builder as connection::Builder>::Output: Unpin + Send,
{
    type Response = MaybeHttpsStream<Http::Response, Builder>;
    type Error = Error;
    type Future = Pin<
        Box<dyn Future<Output = Result<MaybeHttpsStream<Http::Response, Builder>, Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.http.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::HttpError(e.into()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        // Currently, the only supported stream type is TLS. If the application attempts to
        // negotiate HTTP over plain TCP, return an error.
        if req.scheme() == Some(&http::uri::Scheme::HTTP) {
            return Box::pin(async move { Err(Error::InvalidScheme) });
        }

        // Attempt to negotiate HTTP/2.
        let builder = connection::ModifiedBuilder::new(self.conn_builder.clone(), |conn| {
            conn.set_application_protocol_preference([b"h2"])
        });

        let host = req.host().unwrap_or("").to_owned();
        let call = self.http.call(req);
        Box::pin(async move {
            // `HttpsConnector` wraps an HTTP connector that also implements `Service<Uri>`.
            // `call()` is invoked on the wrapped connector to get the underlying hyper TCP stream,
            // which is converted into a tokio-compatible stream with `hyper_util::rt::TokioIo`.
            let tcp = call.await.map_err(|e| Error::HttpError(e.into()))?;
            let tcp = TokioIo::new(tcp);

            let connector = TlsConnector::new(builder);
            let tls = connector
                .connect(&host, tcp)
                .await
                .map_err(Error::TlsError)?;

            Ok(MaybeHttpsStream::Https(TokioIo::new(tls)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Empty;
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};
    use std::{error::Error as StdError, str::FromStr};

    #[tokio::test]
    async fn test_unsecure_http() -> Result<(), Box<dyn StdError>> {
        let connector = HttpsConnector::new(Config::default());
        let client: Client<_, Empty<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let uri = Uri::from_str("http://www.amazon.com")?;
        let error = client.get(uri).await.unwrap_err();

        // Ensure that an InvalidScheme error is returned when HTTP over TCP is attempted.
        let error = error.source().unwrap().downcast_ref::<Error>().unwrap();
        assert!(matches!(error, Error::InvalidScheme));

        // Ensure that the error can produce a valid message
        assert!(!error.to_string().is_empty());

        Ok(())
    }
}
