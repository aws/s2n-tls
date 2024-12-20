// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Support for asynchronous callbacks.
//!
//! The general flow for an async callback is:
//! 1. The application sets FooCallback on the [`crate::config::Config`] with
//!    a method like Config::set_foo_callback.
//! 2. When the underlying C library reaches the trigger for that specific
//!    callback (for example, the ClientHello for [`crate::callbacks::ClientHelloCallback`])
//!    it calls the callback implementation to get a [`ConnectionFuture`].
//! 3. The [`ConnectionFuture`] is stored on the connection. Every time
//!    the handshake is polled, the [`ConnectionFuture`] is polled instead.
//! 4. Once the [`ConnectionFuture`] returns a result, the connection
//!    drops the future and proceeds as usual.

use crate::{connection::Connection, enums::CallbackResult, error::Error};
use core::task::Poll;
use pin_project_lite::pin_project;
use std::pin::Pin;

/// The Future associated with the async connection callback.
///
/// The calling application can provide an instance of [`ConnectionFuture`]
/// when implementing an async callback, eg. [`crate::callbacks::ClientHelloCallback`],
/// if it wants to run an asynchronous operation (disk read, network call).
/// The application can return an error ([Err(Error::application())])
/// to indicate connection failure.
pub trait ConnectionFuture: 'static + Send + Sync {
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), Error>>;
}

pub(crate) type ConnectionFutureResult = Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error>;

// Useful for propagating [`error::Error`] from a C callback back to the Rust application.
pub(crate) struct ErrorFuture {
    error: Option<Error>,
}

impl ConnectionFuture for ErrorFuture {
    fn poll(
        mut self: Pin<&mut Self>,
        _connection: &mut Connection,
        _ctx: &mut core::task::Context,
    ) -> Poll<Result<(), Error>> {
        let err = self.error.take().expect(
            "ErrorFuture should be initialized with Some(error) and a Future should never
            be polled after it returns Poll::Ready",
        );
        Poll::Ready(Err(err))
    }
}

pin_project! {
    /// A wrapper around an optional [`ConnectionFuture`]
    /// which either polls the future or immediately reports success.
    struct OptionalFuture {
        option: Option<Pin<Box<dyn ConnectionFuture>>>,
    }
}

impl OptionalFuture {
    fn new(input: ConnectionFutureResult) -> Self {
        match input {
            Ok(option) => OptionalFuture { option },
            Err(error) => {
                let error = Some(error);
                OptionalFuture {
                    option: Some(Box::pin(ErrorFuture { error })),
                }
            }
        }
    }
}

impl ConnectionFuture for OptionalFuture {
    fn poll(
        mut self: Pin<&mut Self>,
        conn: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), Error>> {
        match self.option.as_mut() {
            Some(future) => future.as_mut().poll(conn, ctx),
            None => Poll::Ready(Ok(())),
        }
    }
}

/// Any work necessary after the callback completes.
//
// We do not expect any callback except [`ClientHelloCallback`] to require MarkDone.
// More recent callbacks follow a different model that doesn't require separate cleanup.
//
// This enum is sufficient while only ClientHello is special-cased, but will not
// scale well. If we need more MarkDone variants, then we should consider a different
// solution, like another stored future.
#[non_exhaustive]
#[derive(PartialEq)]
enum MarkDone {
    ClientHello,
    None,
}

pin_project! {
    // Stores the [`ConnectionFuture`] and associated state.
    pub(crate) struct AsyncCallback {
        #[pin]
        future: OptionalFuture,
        cleanup: MarkDone,
    }
}

impl AsyncCallback {
    pub(crate) fn poll(
        self: Pin<&mut Self>,
        conn: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), Error>> {
        let this = self.project();
        let poll = this.future.poll(conn, ctx);
        if let Poll::Ready(Ok(())) = poll {
            if this.cleanup == &MarkDone::ClientHello {
                conn.mark_client_hello_cb_done()?;
            }
        }
        poll
    }

    pub(crate) fn trigger_client_hello_cb(
        future: ConnectionFutureResult,
        conn: &mut Connection,
    ) -> CallbackResult {
        let future = OptionalFuture::new(future);
        let cleanup = MarkDone::ClientHello;
        let callback = AsyncCallback { future, cleanup };
        conn.set_async_callback(callback);
        CallbackResult::Success
    }

    pub(crate) fn trigger(future: ConnectionFutureResult, conn: &mut Connection) -> CallbackResult {
        let future = OptionalFuture::new(future);
        let cleanup = MarkDone::None;
        let callback = AsyncCallback { future, cleanup };
        conn.set_async_callback(callback);
        CallbackResult::Success
    }
}
