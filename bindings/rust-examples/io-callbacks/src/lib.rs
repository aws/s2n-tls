//! This example shows how to setup the unsafe send + recv callbacks for s2n-tls.
//!
//! For progress on offering safe bindings here, follow https://github.com/aws/s2n-tls/issues/6018
//!

pub mod raw_fd;
pub mod tls_stream;

////////////////////////////////////////////////////////////////////////////////
///////////////////// generic Read & Write C callbacks /////////////////////////
////////////////////////////////////////////////////////////////////////////////

use std::ffi::{c_int, c_void};

/// An s2n-tls `send` callback.
///
/// This callback assumes that the underlying IO object follows posix conventions.
/// E.g. a non-blocking send should set the errno to `EWOULDBLOCK` if the send would
/// block.
///
/// Most abstractions, e.g. [`std::net::TcpStream`] already do this.
///
/// This can be used where ctx is a stable pointer to a `T: Write`. For example.
/// ```
/// use std::os::unix::net::UnixStream;
/// use std::pin::Pin;
/// use std::ffi::c_void;
/// use s2n_tls::connection::Connection;
/// use io_callbacks::generic_posix_send_cb;
///
/// let (client_stream, server_stream) = UnixStream::pair().unwrap();
/// // The IO context should be pinned, because s2n-tls holds the raw pointer for
/// // the duration of the connection.
/// let io_context: Pin<Box<UnixStream>> = Box::pin(client_stream);
/// let io_ctx_ptr: *mut c_void = &*io_context as *const UnixStream as *mut c_void;
///
/// let mut conn = Connection::new_client();
/// unsafe { conn.set_send_context(io_ctx_ptr) }.unwrap();
/// conn.set_send_callback(Some(generic_posix_send_cb::<UnixStream>)).unwrap();
/// ```
///
/// # Safety
///
/// * `context` must be a stable (`Pin`) pointer to a `T` that outlives the
///   connection.
/// * The callback forms a `&mut T` from `context`, so no other reference to that
///   `T` may be live while it runs. s2n-tls calls the send/receive callbacks
///   one at a time and never reentrantly per connection, so one context may back
///   both callbacks of the same connection. It must not be shared across
///   connections or driven concurrently.
pub unsafe extern "C" fn generic_posix_send_cb<T: std::io::Write>(
    context: *mut c_void,
    data: *const u8,
    len: u32,
) -> c_int {
    let context: &mut T = &mut *(context as *mut T);
    let data = core::slice::from_raw_parts(data, len as _);
    match context.write(data) {
        Ok(bytes_written) => bytes_written as i32,
        Err(err) => {
            // On -1, s2n-tls reads `errno` to distinguish "would block"
            // (EWOULDBLOCK/EAGAIN -> Poll::Pending) from a fatal error, so set it
            // before returning. Types that hit the syscall directly (e.g.
            // std::net::TcpStream) already leave errno set, making this redundant;
            // but in general the OS error lives in the io::Error, and intervening
            // work (like the log below) can clobber errno. So re-install it last.
            let os_err = err.raw_os_error();
            tracing::trace!("generic send cb: write error: {err}");
            match os_err {
                Some(os_err) => errno::set_errno(errno::Errno(os_err)),
                None => tracing::warn!("Err {err} doesn't have a corresponding os err 😬"),
            }
            -1
        }
    }
}

/// This callback can be used where ctx is a stable pointer to a `T: Read`.
///
/// The underlying transport stream is responsible for populating the errno appropriately.
///
/// A read of `0` is assumed to mean a closed stream. In the case of no data available
/// and a non-blocking IO mode, the io stream should return an Err and set the errno
/// to EWOULDBLOCK.
///
/// # Safety
///
/// * `context` must be a stable (`Pin`) pointer to a `T` that outlives the
///   connection.
/// * The callback forms a `&mut T` from `context`, so no other reference to that
///   `T` may be live while it runs. s2n-tls calls the send/receive callbacks
///   one at a time and never reentrantly per connection, so one context may back
///   both callbacks of the same connection. It must not be shared across
///   connections or driven concurrently.
pub unsafe extern "C" fn generic_posix_recv_cb<T: std::io::Read>(
    context: *mut c_void,
    data: *mut u8,
    len: u32,
) -> c_int {
    let context: &mut T = &mut *(context as *mut T);
    let data = core::slice::from_raw_parts_mut(data, len as _);
    let read_result = context.read(data);
    match read_result {
        Ok(len) => {
            // Note: an in-memory channel (e.g. VecDeque<u8>) returns Ok(0) when
            // empty, but s2n-tls treats a read of 0 as EOF. Such transports must
            // special-case 0 into an EWOULDBLOCK error instead.
            len as c_int
        }
        Err(err) => {
            // On -1, s2n-tls reads `errno` to distinguish "would block"
            // (EWOULDBLOCK/EAGAIN -> Poll::Pending) from a fatal error, so set it
            // before returning. Types that hit the syscall directly (e.g.
            // std::net::TcpStream) already leave errno set, making this redundant;
            // but in general the OS error lives in the io::Error, and intervening
            // work (like the log below) can clobber errno. So re-install it last.
            let os_err = err.raw_os_error();
            tracing::trace!("generic recv cb: read error: {err}");
            match os_err {
                Some(os_err) => errno::set_errno(errno::Errno(os_err)),
                None => tracing::warn!("Err {err} doesn't have a corresponding os err 😬"),
            }
            -1
        }
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use s2n_tls::{callbacks::VerifyHostNameCallback, config::Config, security::DEFAULT_TLS13};

    // NOTE: these certificates are for demonstration/testing purposes only!
    const CA_CERT: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../certs/ca-cert.pem"));
    const SERVER_CHAIN: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../certs/localhost-chain.pem"
    ));
    const SERVER_KEY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../certs/localhost-key.pem"
    ));
    pub(crate) const SERVER_NAME: &str = "localhost";

    /// A host verification callback that only trusts the expected server name.
    struct VerifyLocalhost;
    impl VerifyHostNameCallback for VerifyLocalhost {
        fn verify_host_name(&self, host_name: &str) -> bool {
            host_name == SERVER_NAME
        }
    }

    pub(crate) fn client_config() -> Config {
        let mut builder = Config::builder();
        builder.set_security_policy(&DEFAULT_TLS13).unwrap();
        builder.trust_pem(CA_CERT).unwrap();
        builder.set_verify_host_callback(VerifyLocalhost).unwrap();
        builder.build().unwrap()
    }

    pub(crate) fn server_config() -> Config {
        let mut builder = Config::builder();
        builder.set_security_policy(&DEFAULT_TLS13).unwrap();
        builder.load_pem(SERVER_CHAIN, SERVER_KEY).unwrap();
        builder.build().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{client_config, server_config, SERVER_NAME};
    use s2n_tls::{connection::Connection, enums::Mode, error::Error as S2NError};
    use std::{os::unix::net::UnixStream, task::Poll};

    // s2n-tls handshake driven over a std::os::unix::net::UnixStream pair, using
    // the generic send/recv callbacks defined in this crate.
    #[test]
    fn handshake_over_unix_domain_socket() -> Result<(), S2NError> {
        let (client_stream, server_stream) = UnixStream::pair().unwrap();

        // conceptually, we require a "Pin" because s2n-tls is holding the raw
        // context pointer for the lifetime of the connection
        let server_stream = Box::pin(server_stream);
        let client_stream = Box::pin(client_stream);

        let mut server = {
            let server_config = server_config();
            let mut conn = Connection::new(Mode::Server);
            conn.set_config(server_config)?;

            let io_context = &*server_stream as *const UnixStream as *mut c_void;

            unsafe { conn.set_send_context(io_context) }?;
            conn.set_send_callback(Some(generic_posix_send_cb::<UnixStream>))?;

            unsafe { conn.set_receive_context(io_context) }?;
            conn.set_receive_callback(Some(generic_posix_recv_cb::<UnixStream>))?;

            conn
        };

        let mut client = {
            let server_config = client_config();
            let mut conn = Connection::new(Mode::Client);
            conn.set_config(server_config)?;
            conn.set_server_name(SERVER_NAME)?;

            let io_context = &*client_stream as *const UnixStream as *mut c_void;

            unsafe { conn.set_send_context(io_context) }?;
            conn.set_send_callback(Some(generic_posix_send_cb::<UnixStream>))?;

            unsafe { conn.set_receive_context(io_context) }?;
            conn.set_receive_callback(Some(generic_posix_recv_cb::<UnixStream>))?;

            conn
        };

        // Drive each handshake on its own thread.
        //
        // These sockets are blocking, so a stalled callback blocks the thread
        // instead of returning EWOULDBLOCK; poll_negotiate never yields Pending
        // and the loops below don't spin. The peers need separate threads, or one
        // would block waiting for bytes the other never gets to send. With
        // non-blocking IO a single thread can drive both, but should wait on the
        // fd (poll/select) or a waker rather than spinning on Pending.

        // drive the client handshake
        let client_hs = std::thread::spawn(move || {
            let res = loop {
                match client.poll_negotiate() {
                    Poll::Ready(res) => break res,
                    Poll::Pending => { /* we need to poll again */ }
                };
            };
            assert!(res.is_ok());
            client
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
            server
        });

        client_hs.join().unwrap();
        server_hs.join().unwrap();

        // Note that because s2n-tls takes raw pointers to the underlying stream
        // there is no automatic memory management. It is generally easier to
        // implement a `TlsStream` abstraction that store the Connection alongside
        // it's "owned" transport layer.
        drop(client_stream);
        drop(server_stream);
        Ok(())
    }
}
