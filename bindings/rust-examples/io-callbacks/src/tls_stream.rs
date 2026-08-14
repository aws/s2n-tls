//! A minimal owning wrapper that ties an s2n-tls [`Connection`] to its transport.
//!
//! s2n-tls holds a raw pointer to the IO context for the life of the connection,
//! so the transport must have a stable address and must outlive the connection's
//! use of it. `TlsStream` enforces both by pinning the transport on the heap and
//! owning it alongside the connection.

use std::ffi::c_void;
use std::io::{self, ErrorKind, Read, Write};
use std::ops::Deref;
use std::pin::Pin;
use std::task::Poll;

use s2n_tls::connection::Connection;
use s2n_tls::error::Error;

use crate::{generic_posix_recv_cb, generic_posix_send_cb};

pub struct TlsStream<T> {
    /// The TLS Connection.
    /// 
    /// Internally, this holds references (raw pointers) to `transport`.
    connection: Connection,
    // `Pin<Box<T>>` gives the transport a stable heap address to hand to s2n-tls
    // as the IO context, and guarantees it won't move for the life of the stream.
    // It is never read directly (the callbacks reach it via the raw context
    // pointer); the field exists to own and keep the allocation alive.
    #[allow(dead_code)]
    transport: Pin<Box<T>>,
}

impl<T: Read + Write> TlsStream<T> {
    /// Wire `transport` into `connection` as the send/receive IO context and take
    /// ownership of both.
    pub fn new(mut connection: Connection, transport: T) -> Result<Self, Error> {
        let transport = Box::pin(transport);

        // The context is a stable pointer to the pinned transport. It is only ever
        // dereferenced inside the callbacks, which s2n-tls invokes one at a time,
        // so no two `&mut T` are ever live at once.
        let io_context = &*transport as *const T as *mut c_void;

        connection.set_send_callback(Some(generic_posix_send_cb::<T>))?;
        unsafe { connection.set_send_context(io_context) }?;

        connection.set_receive_callback(Some(generic_posix_recv_cb::<T>))?;
        unsafe { connection.set_receive_context(io_context) }?;

        Ok(Self {
            connection,
            transport,
        })
    }

    /// Drive the TLS handshake.
    pub fn poll_negotiate(&mut self) -> Poll<Result<(), Error>> {
        self.connection.poll_negotiate().map(|res| res.map(|_| ()))
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl<T: Read + Write> Read for TlsStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.connection.poll_recv(buf) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(e)) => Err(io::Error::new(ErrorKind::Other, e)),
            Poll::Pending => Err(io::Error::new(ErrorKind::WouldBlock, "s2n-tls blocked")),
        }
    }
}

impl<T: Read + Write> Write for TlsStream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.connection.poll_send(buf) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(e)) => Err(io::Error::new(ErrorKind::Other, e)),
            Poll::Pending => Err(io::Error::new(ErrorKind::WouldBlock, "s2n-tls blocked")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // no-op poll_send already invoke the transport methods
        Ok(())
    }
}

// implementing deref makes it easy to use getters on the tls stream.
impl<T> Deref for TlsStream<T> {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{client_config, server_config, SERVER_NAME};
    use s2n_tls::enums::Mode;
    use std::os::unix::net::UnixStream;

    // Handshake and exchange application data using `TlsStream`, which owns each
    // transport and wires up the IO callbacks in its constructor.
    #[test]
    fn tls_stream_roundtrip() -> Result<(), Error> {
        const MESSAGE: &[u8] = b"hello from the client";

        let (client_transport, server_transport) = UnixStream::pair().unwrap();

        let mut server_conn = Connection::new(Mode::Server);
        server_conn.set_config(server_config())?;
        let mut server = TlsStream::new(server_conn, server_transport)?;

        let mut client_conn = Connection::new(Mode::Client);
        client_conn.set_config(client_config())?;
        client_conn.set_server_name(SERVER_NAME)?;
        let mut client = TlsStream::new(client_conn, client_transport)?;

        // Blocking sockets, so drive each peer on its own thread (see the note in
        // lib.rs's handshake test).
        let server_hs = std::thread::spawn(move || {
            while server.poll_negotiate().is_pending() {}
            server
        });
        while client.poll_negotiate().is_pending() {}
        let mut server = server_hs.join().unwrap();

        // Application data flows through the standard Read/Write impls.
        client.write_all(MESSAGE).unwrap();

        let mut buf = vec![0u8; MESSAGE.len()];
        server.read_exact(&mut buf).unwrap();
        assert_eq!(buf, MESSAGE);
        Ok(())
    }
}

