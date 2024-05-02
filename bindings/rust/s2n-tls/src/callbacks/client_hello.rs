// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Support for application-implemented ClientHello callbacks.

use crate::{callbacks::*, config::Config, connection::Connection, error::Error};
use core::task::Poll;
use pin_project_lite::pin_project;
use std::{future::Future, pin::Pin};

/// A trait for the callback executed after parsing the ClientHello message.
///
/// Use in conjunction with
/// [config::Builder::set_client_hello_callback](`crate::config::Builder::set_client_hello_callback()`).
pub trait ClientHelloCallback: 'static + Send + Sync {
    /// The application can return an `Ok(None)` to resolve the callback
    /// synchronously or return an `Ok(Some(ConnectionFuture))` if it wants to
    /// run some asynchronous task before resolving the callback.
    ///
    /// [`ConfigResolver`], which implements [`ConnectionFuture`] can be
    /// returned if the application wants to set a new [`Config`] on the connection.
    ///
    /// If the server_name is used to configure the connection then the application
    /// should call [`Connection::server_name_extension_used()`].
    fn on_client_hello(
        // this method takes an immutable reference to self to prevent the
        // Config from being mutated by one connection and then used in another
        // connection, leading to undefined behavior
        &self,
        connection: &mut Connection,
    ) -> ConnectionFutureResult;
}

// For more information on projection:
// https://doc.rust-lang.org/std/pin/index.html#projections-and-structural-pinning
pin_project! {
    /// An implementation of [`ConnectionFuture`] which resolves the provided
    /// future and sets the config on the [`Connection`].
    pub struct ConfigResolver<F: Future<Output = Result<Config, Error>>> {
        #[pin]
        fut: F,
    }
}

impl<F: 'static + Send + Future<Output = Result<Config, Error>>> ConfigResolver<F> {
    pub fn new(fut: F) -> Self {
        ConfigResolver { fut }
    }
}

impl<F: 'static + Send + Sync + Future<Output = Result<Config, Error>>> ConnectionFuture
    for ConfigResolver<F>
{
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), Error>> {
        let this = self.project();
        let config = match this.fut.poll(ctx) {
            Poll::Ready(config) => config?,
            Poll::Pending => return Poll::Pending,
        };

        connection.set_config(config)?;

        Poll::Ready(Ok(()))
    }
}
