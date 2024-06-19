// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::{
    client::legacy::connect::{Connected, Connection},
    rt::TokioIo,
};
use s2n_tls::connection::Builder;
use s2n_tls_tokio::TlsStream;
use std::{
    io::Error,
    pin::Pin,
    task::{Context, Poll},
};

pub enum MaybeHttpsStream<T, B>
where
    T: Read + Write + Connection + Unpin,
    B: Builder,
    <B as Builder>::Output: Unpin,
{
    Https(TokioIo<TlsStream<TokioIo<T>, B::Output>>),
}

impl<T, B> Connection for MaybeHttpsStream<T, B>
where
    T: Read + Write + Connection + Unpin,
    B: Builder,
    <B as Builder>::Output: Unpin,
{
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Https(stream) => stream.inner().get_ref().connected(),
        }
    }
}

impl<T, B> Read for MaybeHttpsStream<T, B>
where
    T: Read + Write + Connection + Unpin,
    B: Builder,
    <B as Builder>::Output: Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), Error>> {
        match Pin::get_mut(self) {
            Self::Https(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<T, B> Write for MaybeHttpsStream<T, B>
where
    T: Read + Write + Connection + Unpin,
    B: Builder,
    <B as Builder>::Output: Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        match Pin::get_mut(self) {
            Self::Https(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Https(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}
