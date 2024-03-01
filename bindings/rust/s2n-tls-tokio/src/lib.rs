// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use errno::{set_errno, Errno};
use s2n_tls::{
    config::Config,
    connection::{Builder, Connection},
    enums::{Blinding, CallbackResult, Mode},
    error::Error,
};
use std::{
    fmt,
    future::Future,
    io,
    os::raw::{c_int, c_void},
    pin::Pin,
    task::{
        Context, Poll,
        Poll::{Pending, Ready},
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{sleep, Duration, Sleep},
};

macro_rules! ready {
    ($x:expr) => {
        match $x {
            Ready(r) => r,
            Pending => return Pending,
        }
    };
}

#[derive(Clone)]
pub struct TlsAcceptor<B: Builder = Config>
where
    <B as Builder>::Output: Unpin,
{
    builder: B,
}

impl<B: Builder> TlsAcceptor<B>
where
    <B as Builder>::Output: Unpin,
{
    pub fn new(builder: B) -> Self {
        TlsAcceptor { builder }
    }

    pub async fn accept<S>(&self, stream: S) -> Result<TlsStream<S, B::Output>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let conn = self.builder.build_connection(Mode::Server)?;
        TlsStream::open(conn, stream).await
    }
}

#[derive(Clone)]
pub struct TlsConnector<B: Builder = Config>
where
    <B as Builder>::Output: Unpin,
{
    builder: B,
}

impl<B: Builder> TlsConnector<B>
where
    <B as Builder>::Output: Unpin,
{
    pub fn new(builder: B) -> Self {
        TlsConnector { builder }
    }

    pub async fn connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> Result<TlsStream<S, B::Output>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut conn = self.builder.build_connection(Mode::Client)?;
        conn.as_mut().set_server_name(domain)?;
        TlsStream::open(conn, stream).await
    }
}

struct TlsHandshake<'a, S, C>
where
    C: AsRef<Connection> + AsMut<Connection> + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    tls: &'a mut TlsStream<S, C>,
    error: Option<Error>,
}

impl<S, C> Future for TlsHandshake<'_, S, C>
where
    C: AsRef<Connection> + AsMut<Connection> + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        // Retrieve a result, either from the stored error
        // or by polling Connection::poll_negotiate().
        // Connection::poll_negotiate() only completes once,
        // regardless of how often this method is polled.
        let result = match self.error.take() {
            Some(err) => Err(err),
            None => {
                let handshake_poll = self.tls.with_io(ctx, |context| {
                    let conn = context.get_mut().as_mut();
                    conn.poll_negotiate().map(|r| r.map(|_| ()))
                });
                ready!(handshake_poll)
            }
        };
        // If the result isn't a fatal error, return it immediately.
        // Otherwise, poll Connection::poll_shutdown().
        //
        // Shutdown is only best-effort.
        // When Connection::poll_shutdown() completes, even with an error,
        // we return the original Connection::poll_negotiate() error.
        match result {
            Ok(r) => Ok(r).into(),
            Err(e) if e.is_retryable() => Err(e).into(),
            Err(e) => match Pin::new(&mut self.tls).poll_shutdown(ctx) {
                Pending => {
                    self.error = Some(e);
                    Pending
                }
                Ready(_) => Err(e).into(),
            },
        }
    }
}

pub struct TlsStream<S, C = Connection>
where
    C: AsRef<Connection> + AsMut<Connection> + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    conn: C,
    stream: S,
    blinding: Option<Pin<Box<Sleep>>>,
    shutdown_error: Option<Error>,
}

impl<S, C> TlsStream<S, C>
where
    C: AsRef<Connection> + AsMut<Connection> + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    ///Access a shared reference to the underlaying io stream
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    ///Access the mutable reference to the underlaying io stream
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    async fn open(mut conn: C, stream: S) -> Result<Self, Error> {
        conn.as_mut().set_blinding(Blinding::SelfService)?;
        let mut tls = TlsStream {
            conn,
            stream,
            blinding: None,
            shutdown_error: None,
        };
        TlsHandshake {
            tls: &mut tls,
            error: None,
        }
        .await?;
        Ok(tls)
    }

    fn with_io<F, R>(&mut self, ctx: &mut Context, action: F) -> Poll<Result<R, Error>>
    where
        F: FnOnce(Pin<&mut Self>) -> Poll<Result<R, Error>>,
    {
        // Setting contexts on a connection is considered unsafe
        // because the raw pointers provide no lifetime or memory guarantees.
        // We protect against this by pinning the stream during the action
        // and clearing the context afterwards.
        unsafe {
            let context = self as *mut Self as *mut c_void;

            self.as_mut().set_receive_callback(Some(Self::recv_io_cb))?;
            self.as_mut().set_send_callback(Some(Self::send_io_cb))?;
            self.as_mut().set_receive_context(context)?;
            self.as_mut().set_send_context(context)?;
            self.as_mut().set_waker(Some(ctx.waker()))?;

            let result = action(Pin::new(self));

            self.as_mut().set_receive_callback(None)?;
            self.as_mut().set_send_callback(None)?;
            self.as_mut().set_receive_context(std::ptr::null_mut())?;
            self.as_mut().set_send_context(std::ptr::null_mut())?;
            self.as_mut().set_waker(None)?;
            result
        }
    }

    fn poll_io<F>(ctx: *mut c_void, action: F) -> c_int
    where
        F: FnOnce(Pin<&mut S>, &mut Context) -> Poll<Result<usize, std::io::Error>>,
    {
        debug_assert_ne!(ctx, std::ptr::null_mut());
        let tls = unsafe { &mut *(ctx as *mut Self) };

        let mut async_context = Context::from_waker(tls.conn.as_ref().waker().unwrap());
        let stream = Pin::new(&mut tls.stream);

        match action(stream, &mut async_context) {
            Poll::Ready(Ok(len)) => len as c_int,
            Poll::Pending => {
                set_errno(Errno(libc::EWOULDBLOCK));
                CallbackResult::Failure.into()
            }
            _ => CallbackResult::Failure.into(),
        }
    }

    unsafe extern "C" fn recv_io_cb(ctx: *mut c_void, buf: *mut u8, len: u32) -> c_int {
        Self::poll_io(ctx, |stream, async_context| {
            let mut dest = ReadBuf::new(std::slice::from_raw_parts_mut(buf, len as usize));
            stream
                .poll_read(async_context, &mut dest)
                .map_ok(|_| dest.filled().len())
        })
    }

    unsafe extern "C" fn send_io_cb(ctx: *mut c_void, buf: *const u8, len: u32) -> c_int {
        Self::poll_io(ctx, |stream, async_context| {
            let src = std::slice::from_raw_parts(buf, len as usize);
            stream.poll_write(async_context, src)
        })
    }

    /// Polls the blinding timer, if there is any.
    ///
    /// s2n has a "blinding" functionality - when a bad behavior from the peer
    /// is detected, sleeps for 10-30 seconds before answering the client
    /// and closing the connection. This mitigates some timing side channels
    /// that could leak information about encrypted data. See the
    /// `s2n_connection_set_blinding` docs for more details.
    ///
    /// For security reasons, to allow for blinding to correctly function,
    /// before dropping an s2n connection, you should wait until either
    /// `poll_blinding` or `poll_shutdown` (which calls `poll_blinding`
    /// internally) returns ready.
    pub fn poll_blinding(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let tls = self.get_mut();

        if tls.blinding.is_none() {
            let delay = tls.as_ref().remaining_blinding_delay()?;
            if !delay.is_zero() {
                // Sleep operates at the milisecond resolution, so add an extra
                // millisecond to account for any stray nanoseconds.
                let safety = Duration::from_millis(1);
                tls.blinding = Some(Box::pin(sleep(delay.saturating_add(safety))));
            }
        };

        if let Some(timer) = tls.blinding.as_mut() {
            ready!(timer.as_mut().poll(ctx));
            tls.blinding = None;
        }

        Poll::Ready(Ok(()))
    }

    pub async fn apply_blinding(&mut self) -> Result<(), Error> {
        ApplyBlinding { stream: self }.await
    }
}

impl<S, C> AsRef<Connection> for TlsStream<S, C>
where
    C: AsRef<Connection> + AsMut<Connection> + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn as_ref(&self) -> &Connection {
        self.conn.as_ref()
    }
}

impl<S, C> AsMut<Connection> for TlsStream<S, C>
where
    C: AsRef<Connection> + AsMut<Connection> + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn as_mut(&mut self) -> &mut Connection {
        self.conn.as_mut()
    }
}

impl<S, C> AsyncRead for TlsStream<S, C>
where
    C: AsRef<Connection> + AsMut<Connection> + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let tls = self.get_mut();
        tls.with_io(ctx, |mut context| {
            context
                .conn
                .as_mut()
                // Safe since poll_recv_uninitialized does not
                // deinitialize any bytes.
                .poll_recv_uninitialized(unsafe { buf.unfilled_mut() })
                .map_ok(|size| {
                    unsafe {
                        // Safe since poll_recv_uninitialized guaranteed
                        // us that the first `size` bytes have been
                        // initialized.
                        buf.assume_init(size);
                    }
                    buf.advance(size);
                })
        })
        .map_err(io::Error::from)
    }
}

impl<S, C> AsyncWrite for TlsStream<S, C>
where
    C: AsRef<Connection> + AsMut<Connection> + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let tls = self.get_mut();
        tls.with_io(ctx, |mut context| context.conn.as_mut().poll_send(buf))
            .map_err(io::Error::from)
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let tls = self.get_mut();

        ready!(tls.with_io(ctx, |mut context| {
            context.conn.as_mut().poll_flush().map(|r| r.map(|_| ()))
        }))
        .map_err(io::Error::from)?;

        Pin::new(&mut tls.stream).poll_flush(ctx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_blinding(ctx))?;

        // s2n_shutdown_send must not be called again if it errors
        if self.shutdown_error.is_none() {
            let result = ready!(self.as_mut().with_io(ctx, |mut context| {
                context
                    .conn
                    .as_mut()
                    .poll_shutdown_send()
                    .map(|r| r.map(|_| ()))
            }));
            if let Err(error) = result {
                self.shutdown_error = Some(error);
                // s2n_shutdown_send only writes, so will never trigger blinding again.
                // So we do not need to poll_blinding again after this error.
            }
        };

        let tcp_result = ready!(Pin::new(&mut self.as_mut().stream).poll_shutdown(ctx));

        if let Some(err) = self.shutdown_error.take() {
            // poll methods shouldn't be called again after returning Ready, but
            // nothing actually prevents it so poll_shutdown should handle it.
            // s2n_shutdown can be polled indefinitely after succeeding, but not after failing.
            // s2n_tls::error::Error isn't cloneable, so we can't just return the same error
            // if poll_shutdown is called again. Instead, save a different error.
            let next_error = Error::application("Shutdown called again after error".into());
            self.shutdown_error = Some(next_error);

            Ready(Err(io::Error::from(err)))
        } else {
            Ready(tcp_result)
        }
    }
}

impl<S, C> fmt::Debug for TlsStream<S, C>
where
    C: AsRef<Connection> + AsMut<Connection> + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("connection", self.as_ref())
            .finish()
    }
}

struct ApplyBlinding<'a, S, C>
where
    C: AsRef<Connection> + AsMut<Connection> + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream: &'a mut TlsStream<S, C>,
}

impl<'a, S, C> Future for ApplyBlinding<'a, S, C>
where
    C: AsRef<Connection> + AsMut<Connection> + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.as_mut().stream).poll_blinding(ctx)
    }
}
