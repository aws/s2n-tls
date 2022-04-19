// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use errno::{set_errno, Errno};
use s2n_tls::raw::{
    config::Config,
    connection::Connection,
    error::Error,
    ffi::{s2n_mode, s2n_status_code},
};
use std::{
    future::Future,
    os::raw::{c_int, c_void},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct TlsAcceptor {
    config: Config,
}

impl TlsAcceptor {
    pub fn new(config: Config) -> Self {
        TlsAcceptor { config }
    }

    pub async fn accept<S>(&self, stream: S) -> Result<TlsStream<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        TlsStream::open(self.config.clone(), s2n_mode::SERVER, stream).await
    }
}

pub struct TlsConnector {
    config: Config,
}

impl TlsConnector {
    pub fn new(config: Config) -> Self {
        TlsConnector { config }
    }

    pub async fn connect<S>(&self, _domain: &str, stream: S) -> Result<TlsStream<S>, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        TlsStream::open(self.config.clone(), s2n_mode::CLIENT, stream).await
    }
}

struct TlsHandshake<'a, S> {
    tls: &'a mut TlsStream<S>,
}

impl<S> Future for TlsHandshake<'_, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.tls.with_io(|context| {
            context.conn.set_waker(Some(cx.waker()))?;
            context.conn.negotiate().map(|r| r.map(|_| ()))
        })
    }
}

pub struct TlsStream<S> {
    conn: Connection,
    stream: S,
}

impl<S> TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn open(config: Config, mode: s2n_mode::Type, stream: S) -> Result<Self, Error> {
        let mut conn = Connection::new(mode);
        conn.set_config(config)?;

        let mut tls = TlsStream { conn, stream };
        TlsHandshake { tls: &mut tls }.await?;
        Ok(tls)
    }

    fn with_io<F>(&mut self, action: F) -> Poll<Result<(), Error>>
    where
        F: FnOnce(&mut Self) -> Poll<Result<(), Error>>,
    {
        // Setting contexts on a connection is considered unsafe
        // because the raw pointers provide no lifetime or memory guarantees.
        // We protect against this by setting the contexts only for
        // the duration of the action, then clearing them.
        unsafe {
            let context = self as *mut Self as *mut c_void;

            self.conn.set_receive_callback(Some(Self::recv_io_cb))?;
            self.conn.set_send_callback(Some(Self::send_io_cb))?;
            self.conn.set_receive_context(context)?;
            self.conn.set_send_context(context)?;

            let result = action(self);

            self.conn.set_receive_callback(None)?;
            self.conn.set_send_callback(None)?;
            self.conn.set_receive_context(std::ptr::null_mut())?;
            self.conn.set_send_context(std::ptr::null_mut())?;
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
                s2n_status_code::FAILURE
            }
            _ => s2n_status_code::FAILURE,
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
}
