// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::config::Config;
use s2n_tls_tokio::TlsAcceptor;
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const READ_NOT_CALLED: usize = usize::MAX;

struct ReadBufInspector {
    initialized_len: Arc<AtomicUsize>,
}

impl AsyncRead for ReadBufInspector {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let _ = self.initialized_len.compare_exchange(
            READ_NOT_CALLED,
            buf.initialized().len(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ReadBufInspector {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn recv_io_cb_does_not_assume_buffer_initialized() -> Result<(), Box<dyn std::error::Error>> {
    let initialized_len = Arc::new(AtomicUsize::new(READ_NOT_CALLED));
    let stream = ReadBufInspector {
        initialized_len: initialized_len.clone(),
    };

    let mut config = Config::builder();
    config.with_system_certs(false)?;
    let acceptor = TlsAcceptor::new(config.build()?);

    let result = acceptor.accept(stream).await;
    assert!(
        result.is_err(),
        "the EOF transport should fail the handshake"
    );
    assert_eq!(initialized_len.load(Ordering::SeqCst), 0);

    Ok(())
}
