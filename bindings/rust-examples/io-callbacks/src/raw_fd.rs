// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A minimal transport type built directly on a raw file descriptor.
//!
//! This models the kind of integration where you don't have a rich Rust type
//! like [`std::net::TcpStream`] to hand to s2n-tls. Across an FFI or JNI
//! boundary the foreign runtime frequently hands you a bare integer file
//! descriptor instead. By implementing [`std::io::Read`] and [`std::io::Write`]
//! directly over the fd with posix syscalls, the fd can be plugged straight
//! into the generic send/recv callbacks defined in this crate.

use std::ffi::c_void;
use std::io::{Read, Write};
use std::os::fd::RawFd;

/// A newtype wrapper around a raw file descriptor that implements
/// [`Read`] and [`Write`] via posix `read`/`write` syscalls.
///
/// `RawFdStream` takes ownership of the fd and closes it on drop.
pub struct RawFdStream {
    fd: RawFd,
}

impl RawFdStream {
    /// Take *ownership* of `fd`; it is closed via `close(2)` on drop.
    ///
    /// Only pass an fd you own and nothing else will close. In FFI/JNI settings
    /// the fd is often owned by the foreign runtime (e.g. the JVM); handing such
    /// a borrowed fd here causes a double-close. For borrowed fds, use a wrapper
    /// without `Drop` (or a [`std::os::fd::BorrowedFd`]).
    pub fn from_owned(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl Read for RawFdStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: `buf` is a valid, writable slice of length `buf.len()`, and
        // `self.fd` is a file descriptor we own.
        let res = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if res < 0 {
            // Surface the OS error so the generic recv callback can propagate
            // the errno (e.g. EWOULDBLOCK) back to s2n-tls.
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res as usize)
        }
    }
}

impl Write for RawFdStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // SAFETY: `buf` is a valid, readable slice of length `buf.len()`, and
        // `self.fd` is a file descriptor we own.
        let res = unsafe { libc::write(self.fd, buf.as_ptr() as *const c_void, buf.len()) };
        if res < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Raw writes go straight to the kernel, so there is nothing to flush.
        Ok(())
    }
}

impl Drop for RawFdStream {
    fn drop(&mut self) {
        // SAFETY: we own `self.fd` (it was handed to us via `from_owned`), so it
        // is valid to close it here. This prevents the fd from leaking.
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generic_posix_recv_cb, generic_posix_send_cb,
        test_utils::{client_config, server_config, SERVER_NAME},
    };
    use s2n_tls::{connection::Connection, enums::Mode, error::Error as S2NError};
    use std::{
        net::{TcpListener, TcpStream},
        os::fd::IntoRawFd,
        task::Poll,
    };

    // s2n-tls handshake driven over raw file descriptors, using the generic
    // send/recv callbacks defined in this crate.
    //
    // This models an FFI/JNI style integration: rather than handing s2n-tls a
    // rich Rust type, we only have bare file descriptors. We wrap each fd in the
    // `RawFdStream` newtype (which implements Read/Write via posix syscalls) and
    // use that as the IO context.
    #[test]
    fn handshake_over_raw_fd() -> Result<(), S2NError> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept the server side of the connection on a background thread while the
        // main thread connects as the client.
        let accept = std::thread::spawn(move || listener.accept().unwrap().0);
        let client_tcp = TcpStream::connect(addr).unwrap();
        let server_tcp = accept.join().unwrap();

        // Drop down to raw file descriptors. `into_raw_fd` consumes the TcpStream
        // *without* closing the fd, transferring ownership of the fd to us. This is
        // the point where a real integrator would instead receive an fd from their
        // foreign runtime.
        let client_fd = client_tcp.into_raw_fd();
        let server_fd = server_tcp.into_raw_fd();

        // Wrap the raw fds. `RawFdStream` now owns each fd and will close it on drop.
        //
        // conceptually, we require a "Pin" because s2n-tls is holding the raw
        // context pointer for the lifetime of the connection.
        let server_stream = Box::pin(RawFdStream::from_owned(server_fd));
        let client_stream = Box::pin(RawFdStream::from_owned(client_fd));

        let mut server = {
            let mut conn = Connection::new(Mode::Server);
            conn.set_config(server_config())?;

            let io_context = &*server_stream as *const RawFdStream as *mut c_void;

            unsafe { conn.set_send_context(io_context) }?;
            conn.set_send_callback(Some(generic_posix_send_cb::<RawFdStream>))?;

            unsafe { conn.set_receive_context(io_context) }?;
            conn.set_receive_callback(Some(generic_posix_recv_cb::<RawFdStream>))?;

            conn
        };

        let mut client = {
            let mut conn = Connection::new(Mode::Client);
            conn.set_config(client_config())?;
            conn.set_server_name(SERVER_NAME)?;

            let io_context = &*client_stream as *const RawFdStream as *mut c_void;

            unsafe { conn.set_send_context(io_context) }?;
            conn.set_send_callback(Some(generic_posix_send_cb::<RawFdStream>))?;

            unsafe { conn.set_receive_context(io_context) }?;
            conn.set_receive_callback(Some(generic_posix_recv_cb::<RawFdStream>))?;

            conn
        };

        // drive the client handshake
        let client_hs = std::thread::spawn(move || {
            let res = loop {
                match client.poll_negotiate() {
                    Poll::Ready(res) => break res,
                    Poll::Pending => { /* we need to poll again */ }
                };
            };
            assert!(res.is_ok());
        });

        // drive the server handshake
        let server_hs = std::thread::spawn(move || {
            let res = loop {
                match server.poll_negotiate() {
                    Poll::Ready(res) => break res,
                    Poll::Pending => { /* we need to poll again */ }
                };
            };
            assert!(res.is_ok());
        });

        client_hs.join().unwrap();
        server_hs.join().unwrap();

        // Note that because s2n-tls takes raw pointers to the underlying stream
        // there is no automatic memory management. It is generally easier to
        // implement a `TlsStream` abstraction that stores the Connection alongside
        // its "owned" transport layer. Dropping the streams here closes the
        // underlying file descriptors.
        drop(client_stream);
        drop(server_stream);
        Ok(())
    }
}
