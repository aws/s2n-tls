// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

type ReadFn = Box<dyn Fn(Pin<&mut TcpStream>, &mut Context, &mut ReadBuf) -> Poll<io::Result<()>>>;
type WriteFn = Box<dyn Fn(Pin<&mut TcpStream>, &mut Context, &[u8]) -> Poll<io::Result<usize>>>;
type ShutdownFn = Box<dyn Fn(Pin<&mut TcpStream>, &mut Context) -> Poll<io::Result<()>>>;

#[derive(Default)]
struct OverrideMethods {
    next_read: Option<ReadFn>,
    next_write: Option<WriteFn>,
    next_shutdown: Option<ShutdownFn>,
}

#[derive(Default)]
pub struct Overrides(Mutex<OverrideMethods>);

impl Overrides {
    pub fn next_read(&self, input: Option<ReadFn>) {
        if let Ok(mut overrides) = self.0.lock() {
            overrides.next_read = input;
        }
    }

    pub fn next_write(&self, input: Option<WriteFn>) {
        if let Ok(mut overrides) = self.0.lock() {
            overrides.next_write = input;
        }
    }

    pub fn next_shutdown(&self, input: Option<ShutdownFn>) {
        if let Ok(mut overrides) = self.0.lock() {
            overrides.next_shutdown = input;
        }
    }

    pub fn is_consumed(&self) -> bool {
        if let Ok(overrides) = self.0.lock() {
            overrides.next_read.is_none()
                && overrides.next_write.is_none()
                && overrides.next_shutdown.is_none()
        } else {
            false
        }
    }
}

unsafe impl Send for Overrides {}
unsafe impl Sync for Overrides {}

pub struct TestStream {
    stream: TcpStream,
    overrides: Arc<Overrides>,
}

impl TestStream {
    pub fn new(stream: TcpStream) -> Self {
        let overrides = Arc::new(Overrides::default());
        Self { stream, overrides }
    }

    pub fn overrides(&self) -> Arc<Overrides> {
        self.overrides.clone()
    }
}

impl AsyncRead for TestStream {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        let stream = Pin::new(&mut s.stream);
        let action = match s.overrides.0.lock() {
            Ok(mut overrides) => overrides.next_read.take(),
            _ => None,
        };
        if let Some(f) = action {
            (f)(stream, ctx, buf)
        } else {
            stream.poll_read(ctx, buf)
        }
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let s = self.get_mut();
        let stream = Pin::new(&mut s.stream);
        let action = match s.overrides.0.lock() {
            Ok(mut overrides) => overrides.next_write.take(),
            _ => None,
        };
        if let Some(f) = action {
            (f)(stream, ctx, buf)
        } else {
            stream.poll_write(ctx, buf)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(ctx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        let stream = Pin::new(&mut s.stream);
        let action = match s.overrides.0.lock() {
            Ok(mut overrides) => overrides.next_shutdown.take(),
            _ => None,
        };
        if let Some(f) = action {
            (f)(stream, ctx)
        } else {
            stream.poll_shutdown(ctx)
        }
    }
}
