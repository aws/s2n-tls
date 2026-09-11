// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! An mTLS server that validates the client certificate against a Certificate
//! Revocation List (CRL) fetched *asynchronously*.
//!
//! The certificate validation callback runs after s2n-tls has already performed
//! its built-in verification of the client's certificate chain. Fetching a CRL
//! typically requires a network round-trip, which we do NOT want to perform on
//! the handshake thread. [`NetworkCrlFetcher`] therefore returns a
//! [`ConnectionFuture`]: the handshake pauses (without blocking the tokio
//! runtime) until the fetch resolves, at which point the future accepts or
//! rejects the certificate.

use clap::Parser;
use s2n_tls::{
    callbacks::{CertValidationCallback, CertValidationInfo, ConnectionFuture},
    callbacks::VerifyHostNameCallback,
    connection::Connection,
    enums::ClientAuthType,
    error::Error as S2NError,
    security::DEFAULT_TLS13,
};
use s2n_tls_tokio::TlsAcceptor;
use std::{
    future::Future,
    hash::{Hash, Hasher},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::*};

const PORT: u16 = 1739;

/// An async certificate validation callback that checks the peer's certificate
/// against a CRL fetched over the network.
#[derive(Clone)]
struct NetworkCrlFetcher {
    /// The CRL distribution point. In this example it is only used for logging;
    /// a real implementation would issue a request to this endpoint.
    crl_endpoint: String,
    /// Simulates a CRL that revokes every client. Toggled with `--revoke-all`
    /// so the example can demonstrate both the accept and reject paths.
    revoke_all: bool,
}

impl CertValidationCallback for NetworkCrlFetcher {
    fn validate_cert(
        &self,
        connection: &mut Connection,
        info: CertValidationInfo,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, S2NError> {
        // Identify the peer (client) certificate. A real CRL check keys off the
        // certificate's serial number; here we derive a stable fingerprint from
        // the leaf certificate's DER encoding to stand in for that identity.
        let chain = connection.peer_cert_chain()?;
        let leaf = chain
            .iter()
            .next()
            .ok_or_else(|| S2NError::application("empty peer cert chain".into()))??;
        let fingerprint = fingerprint(leaf.der()?);

        let endpoint = self.crl_endpoint.clone();
        let revoke_all = self.revoke_all;

        // Perform the CRL fetch asynchronously. While this future is pending the
        // handshake is paused, so the tokio runtime is free to drive other
        // connections instead of blocking on the network round-trip.
        let check = Box::pin(async move {
            println!("fetching CRL from {endpoint} for client 0x{fingerprint:016x}");
            let revoked = fetch_and_check_crl(&endpoint, fingerprint, revoke_all).await?;
            if revoked {
                println!("client 0x{fingerprint:016x} is REVOKED");
            } else {
                println!("client 0x{fingerprint:016x} is valid");
            }
            // The CRL check resolves to "should we accept the certificate?".
            Ok(!revoked)
        });

        Ok(Some(Box::pin(CrlValidationFuture {
            check,
            info: Some(info),
        })))
    }
}

/// The [`ConnectionFuture`] that drives the CRL fetch to completion and then
/// resolves the validation.
struct CrlValidationFuture {
    // Resolves to `true` to accept the certificate, `false` to reject it.
    check: Pin<Box<dyn Future<Output = Result<bool, S2NError>> + Send + Sync>>,
    info: Option<CertValidationInfo>,
}

impl ConnectionFuture for CrlValidationFuture {
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut Connection,
        ctx: &mut Context,
    ) -> Poll<Result<(), S2NError>> {
        // None of the fields are structurally pinned (`Pin<Box<_>>` is `Unpin`),
        // so we can safely get a mutable reference to the inner fields.
        let this = self.get_mut();
        match this.check.as_mut().poll(ctx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(accept)) => {
                let info = this
                    .info
                    .take()
                    .expect("future should not be polled after it resolves");
                // SAFETY: the info is resolved from within `poll`, where the
                // owning connection (passed as `connection`) is alive.
                let result = if accept {
                    unsafe { info.accept(connection) }
                } else {
                    unsafe { info.reject(connection) }
                };
                Poll::Ready(result)
            }
        }
    }
}

/// Simulates fetching a CRL from `endpoint` and checking whether `fingerprint`
/// is revoked.
///
/// To keep the example self-contained, the "network fetch" is modeled with an
/// async delay rather than a real HTTP request. In production this is where you
/// would issue the request (e.g. with an async HTTP client) and parse the
/// returned CRL. Because it is `.await`ed inside a [`ConnectionFuture`], the
/// work happens off the handshake thread.
async fn fetch_and_check_crl(
    _endpoint: &str,
    _fingerprint: u64,
    revoke_all: bool,
) -> Result<bool, S2NError> {
    tokio::time::sleep(Duration::from_millis(200)).await;
    // A real implementation would test `fingerprint` for membership in the
    // downloaded CRL. This example uses a fixed policy instead.
    Ok(revoke_all)
}

/// Derives a stable identifier from a certificate's DER encoding, used here as a
/// stand-in for the certificate serial number.
fn fingerprint(der: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    der.hash(&mut hasher);
    hasher.finish()
}

/// The server validates the client certificate against the trusted CA, so host
/// name verification of the client is not meaningful. Accept any name.
struct AcceptAllHostNames;
impl VerifyHostNameCallback for AcceptAllHostNames {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}

#[derive(Debug, Parser)]
struct Cli {
    /// Simulate a CRL that revokes every client certificate.
    #[arg(long)]
    revoke_all: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    let certs = format!("{}/../certs", env!("CARGO_MANIFEST_DIR"));

    let fetcher = NetworkCrlFetcher {
        crl_endpoint: "http://crl.example.com/clients.crl".to_owned(),
        revoke_all: args.revoke_all,
    };

    let mut config = s2n_tls::config::Builder::new();
    config.set_security_policy(&DEFAULT_TLS13)?;
    // Present the server's own certificate.
    config.load_pem(
        &std::fs::read(format!("{certs}/localhost-chain.pem"))?,
        &std::fs::read(format!("{certs}/localhost-key.pem"))?,
    )?;
    // Require and trust client certificates (mutual TLS).
    config.set_client_auth_type(ClientAuthType::Required)?;
    config.trust_pem(&std::fs::read(format!("{certs}/ca-cert.pem"))?)?;
    config.set_verify_host_callback(AcceptAllHostNames)?;
    // Layer the async CRL check on top of the built-in chain validation.
    config.set_cert_validation_callback(fetcher)?;

    let server = TlsAcceptor::new(config.build()?);

    let listener = TcpListener::bind(&format!("0.0.0.0:{PORT}")).await?;
    println!("listening on {PORT} (revoke_all = {})", args.revoke_all);
    loop {
        let server = server.clone();
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut tls = match server.accept(stream).await {
                Ok(tls) => tls,
                Err(e) => {
                    println!("handshake rejected: {e}");
                    return Ok(());
                }
            };
            tls.write_all(b"Hello, your client certificate was accepted")
                .await?;
            tls.shutdown().await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
    }
}
