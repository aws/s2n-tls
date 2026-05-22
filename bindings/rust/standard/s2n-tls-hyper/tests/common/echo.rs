// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use s2n_tls::connection::Builder;
use s2n_tls_tokio::TlsAcceptor;
use std::{error::Error, future::Future};
use tokio::net::TcpListener;

pub async fn echo(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::new(req.into_body().boxed()))
}

pub async fn serve_echo<B>(
    tcp_listener: TcpListener,
    builder: B,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    B: Builder,
    <B as Builder>::Output: Unpin + Send + Sync + 'static,
{
    let (tcp_stream, _) = tcp_listener.accept().await?;
    let acceptor = TlsAcceptor::new(builder);
    let tls_stream = acceptor.accept(tcp_stream).await?;
    let io = TokioIo::new(tls_stream);

    let server = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    if let Err(err) = server.serve_connection(io, service_fn(echo)).await {
        // The hyper client doesn't gracefully terminate by waiting for the server's shutdown.
        // Instead, the client sends its shutdown and then immediately closes the socket. This can
        // cause a NotConnected error to be emitted when the server attempts to send its shutdown.
        //
        // For now, NotConnected errors are ignored. After the hyper client can be configured to
        // gracefully shutdown, this exception can be removed:
        // https://github.com/aws/s2n-tls/issues/4855
        //
        // Also, it's possible that a NotConnected error could occur during some operation other
        // than a shutdown. Ideally, these NotConnected errors wouldn't be ignored. However, it's
        // not currently possible to distinguish between shutdown vs non-shutdown errors:
        // https://github.com/aws/s2n-tls/issues/4856
        if let Some(hyper_err) = err.downcast_ref::<hyper::Error>() {
            if let Some(source) = hyper_err.source() {
                if let Some(io_err) = source.downcast_ref::<tokio::io::Error>() {
                    if io_err.kind() == tokio::io::ErrorKind::NotConnected {
                        return Ok(());
                    }
                }
            }
        }

        return Err(err);
    }

    Ok(())
}

pub async fn make_echo_request<B, F, Fut>(
    server_builder: B,
    send_client_request: F,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    B: Builder + Send + Sync + 'static,
    <B as Builder>::Output: Unpin + Send + Sync + 'static,
    F: FnOnce(u16) -> Fut,
    Fut: Future<Output = Result<(), Box<dyn Error + Send + Sync>>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(serve_echo(listener, server_builder));
    tasks.spawn(send_client_request(addr.port()));

    while let Some(res) = tasks.join_next().await {
        res.unwrap()?;
    }

    Ok(())
}
