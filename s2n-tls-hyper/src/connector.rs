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
pub struct HttpsConnector<Http, ConnBuilder = Config> {
    http: Http,
    conn_builder: ConnBuilder,
    plaintext_http: bool,
}

impl<ConnBuilder> HttpsConnector<HttpConnector, ConnBuilder>
where
    ConnBuilder: connection::Builder,
    <ConnBuilder as connection::Builder>::Output: Unpin,
{
    /// Creates a new `HttpsConnector` with the default settings.
    ///
    /// Use `HttpsConnector::builder()` instead to configure an `HttpsConnector`.
    ///
    /// `conn_builder` will be used to produce the s2n-tls Connections used for negotiating HTTPS,
    /// which can be an `s2n_tls::config::Config` or other `s2n_tls::connection::Builder`.
    ///
    /// Note that s2n-tls-hyper will override the ALPN extension to negotiate HTTP. Any ALPN values
    /// configured on `conn_builder` with APIs like
    /// `s2n_tls::config::Builder::set_application_protocol_preference()` will be ignored.
    pub fn new(conn_builder: ConnBuilder) -> HttpsConnector<HttpConnector, ConnBuilder> {
        HttpsConnector::builder(conn_builder).build()
    }

    /// Creates a `Builder` to configure a new `HttpsConnector`.
    ///
    /// `conn_builder` will be used to produce the s2n-tls Connections used for negotiating HTTPS,
    /// which can be an `s2n_tls::config::Config` or other `s2n_tls::connection::Builder`.
    ///
    /// This API creates a `Builder` with the default hyper `HttpConnector`. To use an existing HTTP
    /// connector, use `HttpsConnector::builder_with_http()`.
    ///
    /// Note that s2n-tls-hyper will override the ALPN extension to negotiate HTTP. Any ALPN values
    /// configured on `conn_builder` with APIs like
    /// `s2n_tls::config::Builder::set_application_protocol_preference()` will be ignored.
    pub fn builder(conn_builder: ConnBuilder) -> Builder<HttpConnector, ConnBuilder> {
        let mut http = HttpConnector::new();

        // By default, the `HttpConnector` only allows the HTTP URI scheme to be used. To negotiate
        // HTTP over TLS via the HTTPS scheme, `enforce_http` must be disabled.
        http.enforce_http(false);

        HttpsConnector::builder_with_http(http, conn_builder)
    }
}

impl<Http, ConnBuilder> HttpsConnector<Http, ConnBuilder>
where
    ConnBuilder: connection::Builder,
    <ConnBuilder as connection::Builder>::Output: Unpin,
{
    /// Creates a `Builder` to configure a new `HttpsConnector`.
    ///
    /// `conn_builder` will be used to produce the s2n-tls Connections used for negotiating HTTPS,
    /// which can be an `s2n_tls::config::Config` or other `s2n_tls::connection::Builder`.
    ///
    /// This API allows an `HttpsConnector` to be constructed with an existing HTTP connector, as
    /// follows:
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
    /// let connector = HttpsConnector::builder_with_http(http, Config::default()).build();
    /// ```
    ///
    /// `HttpsConnector::builder()` can be used to create the HTTP connector automatically.
    ///
    /// Note that s2n-tls-hyper will override the ALPN extension to negotiate HTTP. Any ALPN values
    /// configured on `conn_builder` with APIs like
    /// `s2n_tls::config::Builder::set_application_protocol_preference()` will be ignored.
    pub fn builder_with_http(http: Http, conn_builder: ConnBuilder) -> Builder<Http, ConnBuilder> {
        Builder {
            http,
            conn_builder,
            plaintext_http: false,
        }
    }
}

/// Builder used to configure an `HttpsConnector`. Create a new Builder with
/// `HttpsConnector::builder`.
pub struct Builder<Http, ConnBuilder> {
    http: Http,
    conn_builder: ConnBuilder,
    plaintext_http: bool,
}

impl<Http, ConnBuilder> Builder<Http, ConnBuilder> {
    /// If enabled, allows communication with plaintext HTTP endpoints in addition to secure HTTPS
    /// endpoints (default: false).
    pub fn with_plaintext_http(&mut self, enabled: bool) -> &mut Self {
        self.plaintext_http = enabled;
        self
    }

    /// Builds a new `HttpsConnector`.
    pub fn build(self) -> HttpsConnector<Http, ConnBuilder> {
        HttpsConnector {
            http: self.http,
            conn_builder: self.conn_builder,
            plaintext_http: self.plaintext_http,
        }
    }
}

// hyper connectors MUST implement `hyper_util::client::legacy::connect::Connect`, which is an alias
// for the `tower_service::Service` trait where `Service` is implemented for `http::uri::Uri`, and
// `Service::Response` implements traits for compatibility with hyper:
// https://docs.rs/hyper-util/latest/hyper_util/client/legacy/connect/trait.Connect.html
//
// The hyper compatibility traits for `Service::Response` are implemented in `MaybeHttpsStream`.
impl<Http, ConnBuilder> Service<Uri> for HttpsConnector<Http, ConnBuilder>
where
    Http: Service<Uri>,
    Http::Response: Read + Write + Connection + Unpin + Send + 'static,
    Http::Future: Send + 'static,
    Http::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ConnBuilder: connection::Builder + Send + Sync + 'static,
    <ConnBuilder as connection::Builder>::Output: Unpin + Send,
{
    type Response = MaybeHttpsStream<Http::Response, ConnBuilder>;
    type Error = Error;
    type Future = Pin<
        Box<
            dyn Future<Output = Result<MaybeHttpsStream<Http::Response, ConnBuilder>, Error>>
                + Send,
        >,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.http.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::HttpError(e.into()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        match req.scheme() {
            Some(scheme) if scheme == &http::uri::Scheme::HTTPS => (),
            Some(scheme) if scheme == &http::uri::Scheme::HTTP && self.plaintext_http => {
                let call = self.http.call(req);
                return Box::pin(async move {
                    let tcp = call.await.map_err(|e| Error::HttpError(e.into()))?;
                    Ok(MaybeHttpsStream::Http(tcp))
                });
            }
            _ => {
                return Box::pin(async move { Err(Error::InvalidScheme) });
            }
        }

        // Attempt to negotiate HTTP/2 by including it in the ALPN extension. Other supported HTTP
        // versions are also included to prevent the server from rejecting the TLS connection if
        // HTTP/2 isn't supported:
        //
        // https://datatracker.ietf.org/doc/html/rfc7301#section-3.2
        //    In the event that the server supports no
        //    protocols that the client advertises, then the server SHALL respond
        //    with a fatal "no_application_protocol" alert.
        let builder = connection::ModifiedBuilder::new(self.conn_builder.clone(), |conn| {
            conn.set_application_protocol_preference([
                b"h2".to_vec(),
                b"http/1.1".to_vec(),
                b"http/1.0".to_vec(),
            ])
        });

        // IPv6 addresses are enclosed in square brackets within the host of a URI (e.g.
        // `https://[::1:2:3:4]/`). These square brackets aren't part of the domain itself, so they
        // are trimmed off to provide the proper server name to s2n-tls-tokio (e.g. `::1:2:3:4`).
        let mut domain = req.host().unwrap_or("");
        if let Some(trimmed) = domain.strip_prefix('[') {
            if let Some(trimmed) = trimmed.strip_suffix(']') {
                domain = trimmed;
            }
        }
        let domain = domain.to_owned();

        let call = self.http.call(req);
        Box::pin(async move {
            // `HttpsConnector` wraps an HTTP connector that also implements `Service<Uri>`.
            // `call()` is invoked on the wrapped connector to get the underlying hyper TCP stream,
            // which is converted into a tokio-compatible stream with `hyper_util::rt::TokioIo`.
            let tcp = call.await.map_err(|e| Error::HttpError(e.into()))?;
            let tcp = TokioIo::new(tcp);

            let connector = TlsConnector::new(builder);
            let tls = connector
                .connect(&domain, tcp)
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
    async fn connector_creation() {
        let config = Config::default();
        let connector_from_new = HttpsConnector::new(config.clone());
        let _assert_type: HttpsConnector<HttpConnector, Config> = connector_from_new;

        let connector_from_builder = HttpsConnector::builder(config.clone()).build();
        let _assert_type: HttpsConnector<HttpConnector, Config> = connector_from_builder;

        let http: u32 = 10;
        let connector_from_builder_with_http =
            HttpsConnector::builder_with_http(http, config.clone()).build();
        let _assert_type: HttpsConnector<u32, Config> = connector_from_builder_with_http;

        let builder = HttpsConnector::builder(config.clone());
        let connector_from_builder = builder.build();
        let _assert_type: HttpsConnector<HttpConnector, Config> = connector_from_builder;
    }

    #[tokio::test]
    async fn test_invalid_scheme() -> Result<(), Box<dyn StdError>> {
        let connector = HttpsConnector::new(Config::default());
        let client: Client<_, Empty<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        // Attempt to make a request with an arbitrary invalid scheme.
        let uri = Uri::from_str("notascheme://www.amazon.com")?;
        let error = client.get(uri).await.unwrap_err();

        // Ensure that an InvalidScheme error is returned.
        let error = error.source().unwrap().downcast_ref::<Error>().unwrap();
        assert!(matches!(error, Error::InvalidScheme));

        // Ensure that the error can produce a valid message
        assert!(!error.to_string().is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn default_builder() -> Result<(), Box<dyn StdError>> {
        // Ensure that plaintext HTTP is disabled by default.
        let connector = HttpsConnector::builder(Config::default()).build();
        assert!(!connector.plaintext_http);

        Ok(())
    }
}
