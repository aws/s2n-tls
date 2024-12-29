// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{cell::RefCell, collections::VecDeque, io::ErrorKind, pin::Pin, rc::Rc};

pub type LocalDataBuffer = RefCell<VecDeque<u8>>;

#[derive(Debug)]
pub struct TestPairIO {
    /// a data buffer that the server writes to and the client reads from
    pub server_tx_stream: Pin<Rc<LocalDataBuffer>>,
    /// a data buffer that the client writes to and the server reads from
    pub client_tx_stream: Pin<Rc<LocalDataBuffer>>,
}

impl TestPairIO {
    pub fn client_view(&self) -> ViewIO {
        ViewIO {
            send_ctx: self.client_tx_stream.clone(),
            recv_ctx: self.server_tx_stream.clone(),
        }
    }

    pub fn server_view(&self) -> ViewIO {
        ViewIO {
            send_ctx: self.server_tx_stream.clone(),
            recv_ctx: self.client_tx_stream.clone(),
        }
    }
}

/// A "view" of the IO.
///
/// This view is client/server specific, and notably implements the read and write
/// traits.
///
// This struct is used by Openssl and Rustls which both rely on a "stream" abstraction
// which implements read and write. This is not used by s2n-tls, which relies on
// lower level callbacks.
pub struct ViewIO {
    pub send_ctx: Pin<Rc<LocalDataBuffer>>,
    pub recv_ctx: Pin<Rc<LocalDataBuffer>>,
}

impl std::io::Read for ViewIO {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let res = self.recv_ctx.borrow_mut().read(buf);
        if let Ok(0) = res {
            // We are "faking" a TcpStream, where a read of length 0 indicates
            // EoF. That is incorrect for this scenario. Instead we return WouldBlock
            // to indicate that there is simply no more data to be read.
            Err(std::io::Error::new(ErrorKind::WouldBlock, "blocking"))
        } else {
            res
        }
    }
}

impl std::io::Write for ViewIO {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.send_ctx.borrow_mut().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
