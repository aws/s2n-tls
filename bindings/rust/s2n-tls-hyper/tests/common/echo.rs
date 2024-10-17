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

async fn echo(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::new(req.into_body().boxed()))
}

async fn serve_echo<B>(
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
    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection(io, service_fn(echo))
        .await?;
    Ok(())
}

pub async fn make_echo_request<B, F, Fut>(
    server_builder: B,
    on_init: F,
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

    // Allow the server to start listening.
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    tasks.spawn(on_init(addr.port()));

    while let Some(res) = tasks.join_next().await {
        res.unwrap()?;
    }

    Ok(())
}
