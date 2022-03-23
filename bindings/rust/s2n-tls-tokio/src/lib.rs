// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use errno::{set_errno, Errno};
use s2n_tls::raw::{config::Config, connection::Connection, error::Error, ffi::s2n_mode};
use std::{
    future::Future,
    os::raw::{c_int, c_void},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const IO_ERROR_RETURN: c_int = -1;

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
        self.tls.set_io_ctx()?;
        self.tls.conn.set_waker(Some(cx.waker()))?;
        self.tls.conn.negotiate().map(|r| r.map(|_| ()))
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
    async fn open(config: Config, mode: s2n_mode::Type, stream: S) -> Result<TlsStream<S>, Error> {
        let mut conn = Connection::new(mode);
        conn.set_config(config)?;

        conn.set_receive_callback(Some(Self::recv_io_cb))?;
        conn.set_send_callback(Some(Self::send_io_cb))?;

        let mut tls = TlsStream { conn, stream };
        TlsHandshake { tls: &mut tls }.await?;
        Ok(tls)
    }

    fn set_io_ctx(&mut self) -> Result<(), Error> {
        unsafe {
            let context = self as *mut TlsStream<S> as *mut c_void;
            self.conn.set_receive_context(context)?;
            self.conn.set_send_context(context)?;
        }
        Ok(())
    }

    fn poll_io<F>(ctx: *mut c_void, mut action: F) -> c_int
    where
        F: FnMut(&mut Context, Pin<&mut S>) -> Poll<Result<usize, std::io::Error>>,
    {
        assert!(ctx != std::ptr::null_mut());
        let tls = unsafe { &mut *(ctx as *mut TlsStream<S>) };

        let mut async_context = Context::from_waker(tls.conn.waker().unwrap());
        let stream = Pin::new(&mut tls.stream);

        match action(&mut async_context, stream) {
            Poll::Ready(Ok(len)) => len as c_int,
            Poll::Pending => {
                set_errno(Errno(libc::EWOULDBLOCK));
                IO_ERROR_RETURN
            }
            _ => {
                println!("Oh no io");
                IO_ERROR_RETURN
            }
        }
    }

    unsafe extern "C" fn recv_io_cb(ctx: *mut c_void, buf: *mut u8, len: u32) -> c_int {
        Self::poll_io(ctx, |async_context, stream| {
            let mut dest = ReadBuf::new(std::slice::from_raw_parts_mut(buf, len as usize));
            stream
                .poll_read(async_context, &mut dest)
                .map_ok(|_| dest.filled().len())
        })
    }

    unsafe extern "C" fn send_io_cb(ctx: *mut c_void, buf: *const u8, len: u32) -> c_int {
        Self::poll_io(ctx, |async_context, stream| {
            let src = std::slice::from_raw_parts(buf, len as usize);
            stream.poll_write(async_context, src)
        })
    }
}
