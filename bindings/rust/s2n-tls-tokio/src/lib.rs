// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use errno::{set_errno, Errno};
use s2n_tls::raw::{
    connection::Connection,
    enums::{CallbackResult, Mode},
    error::Error,
};
use std::{
    fmt,
    future::Future,
    io,
    os::raw::{c_int, c_void},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub mod builder;
pub use builder::*;

#[derive(Clone)]
pub struct TlsAcceptor<T: Builder> {
    config: T,
}

impl<T: Builder> TlsAcceptor<T> {
    pub fn new(config: T) -> Self {
        TlsAcceptor { config }
    }

    pub async fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        TlsStream::open(&self.config, Mode::Server, stream).await
    }
}

#[derive(Clone)]
pub struct TlsConnector<T: Builder> {
    config: T,
}

impl<T: Builder> TlsConnector<T> {
    pub fn new(config: T) -> Self {
        TlsConnector { config }
    }

    pub async fn connect<S>(&self, domain: &str, stream: S) -> Result<TlsStream<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let config = |mode| {
            let mut conn = self.config.build(mode)?;
            conn.set_server_name(domain)?;
            Ok(conn)
        };
        TlsStream::open(&config, Mode::Client, stream).await
    }
}

struct TlsHandshake<'a, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tls: &'a mut TlsStream<S>,
}

impl<S> Future for TlsHandshake<'_, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        self.tls.with_io(ctx, |context| {
            let conn = context.get_mut().get_mut();
            conn.negotiate().map(|r| r.map(|_| ()))
        })
    }
}

pub struct TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    conn: Connection,
    stream: S,
}

impl<S> TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn open<T: Builder>(config: &T, mode: Mode, stream: S) -> Result<Self, Error> {
        let conn = config.build(mode)?;
        let mut tls = TlsStream { conn, stream };
        TlsHandshake { tls: &mut tls }.await?;
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

            self.conn.set_receive_callback(Some(Self::recv_io_cb))?;
            self.conn.set_send_callback(Some(Self::send_io_cb))?;
            self.conn.set_receive_context(context)?;
            self.conn.set_send_context(context)?;
            self.conn.set_waker(Some(ctx.waker()))?;

            let result = action(Pin::new(self));

            self.conn.set_receive_callback(None)?;
            self.conn.set_send_callback(None)?;
            self.conn.set_receive_context(std::ptr::null_mut())?;
            self.conn.set_send_context(std::ptr::null_mut())?;
            self.conn.set_waker(None)?;
            result
        }
    }

    fn poll_io<F>(ctx: *mut c_void, action: F) -> c_int
    where
        F: FnOnce(Pin<&mut S>, &mut Context) -> Poll<Result<usize, std::io::Error>>,
    {
        debug_assert_ne!(ctx, std::ptr::null_mut());
        let tls = unsafe { &mut *(ctx as *mut Self) };

        let mut async_context = Context::from_waker(tls.conn.waker().unwrap());
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

    pub fn get_ref(&self) -> &Connection {
        &self.conn
    }

    pub fn get_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_io(ctx, |mut context| {
                context.conn.recv(buf.initialize_unfilled()).map_ok(|size| {
                    buf.advance(size);
                })
            })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .with_io(ctx, |mut context| context.conn.send(buf))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let tls = self.get_mut();
        let tls_flush = tls
            .with_io(ctx, |mut context| {
                context.conn.flush().map(|r| r.map(|_| ()))
            })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));
        if tls_flush.is_ready() {
            Pin::new(&mut tls.stream).poll_flush(ctx)
        } else {
            tls_flush
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let tls = self.get_mut();
        let tls_shutdown = tls
            .with_io(ctx, |mut context| {
                context.conn.shutdown().map(|r| r.map(|_| ()))
            })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));
        if tls_shutdown.is_ready() {
            Pin::new(&mut tls.stream).poll_shutdown(ctx)
        } else {
            tls_shutdown
        }
    }
}

impl<S> fmt::Debug for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("connection", &self.conn)
            .finish()
    }
}
