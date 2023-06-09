use crate::TlsImpl;
use s2n_tls::{
    callbacks::VerifyHostNameCallback,
    config::Builder,
    connection::Connection,
    enums::{Blinding, Mode},
    security::DEFAULT_TLS13,
};
use std::{
    ffi::c_void,
    io::{Read, Write},
    os::raw::c_int,
    pin::Pin,
    task::Poll::Ready,
};

pub struct S2nTls {}

// TODO: use something other than Vec<u8> (BytesMut? VecDeque<Bytes>?)
// TODO: change visibilities of functions
// TODO: refactor to have common harness
// TODO: add comments

struct Buffer {
    bytes: Vec<u8>,
}

impl Buffer {
    fn new() -> Self {
        Buffer { bytes: Vec::new() }
    }
}

impl Read for Buffer {
    fn read(&mut self, dest: &mut [u8]) -> Result<usize, std::io::Error> {
        let avail_len = self.bytes.len();
        if dest.len() > avail_len {
            // enough space in dest, read all contents to dest
            dest[..avail_len].copy_from_slice(&self.bytes);
            self.bytes.clear();
            Ok(avail_len)
        } else {
            // dest too small, fill up dest
            let remaining = self.bytes.split_off(dest.len());
            dest.copy_from_slice(&self.bytes);
            self.bytes = remaining;
            Ok(dest.len())
        }
    }
}

impl Write for Buffer {
    fn write(&mut self, src: &[u8]) -> Result<usize, std::io::Error> {
        self.bytes.extend_from_slice(src);
        Ok(src.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        // data always already in destination
        Ok(())
    }
}

/// Custom callback for verifying hostnames, mandatory to use s2n-tls
pub struct HostNameHandler<'a> {
    hostname: &'a str,
}
impl VerifyHostNameCallback for HostNameHandler<'_> {
    fn verify_host_name(&self, hostname: &str) -> bool {
        self.hostname == hostname
    }
}

impl S2nTls {
    unsafe extern "C" fn send_cb(context: *mut c_void, data: *const u8, len: u32) -> c_int {
        let context = &mut *(context as *mut Buffer);
        let data = core::slice::from_raw_parts(data, len as _);
        let ans = context.write(data).unwrap() as _;
        println!("sent {ans}");
        ans
    }

    unsafe extern "C" fn recv_cb(context: *mut c_void, data: *mut u8, len: u32) -> c_int {
        let context = &mut *(context as *mut Buffer);
        let mut data = core::slice::from_raw_parts_mut(data, len as _);
        context.flush().unwrap();
        let ans = context.read(&mut data).unwrap() as _;
        println!("received {ans}");
        if ans == 0 {
            errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
            -1
        } else {
            ans
        }
    }

    fn get_root_cert() -> &'static [u8] {
        include_bytes!("certs-quic/certs/ca-cert.pem")
    }

    fn get_cert_chain() -> &'static [u8] {
        include_bytes!("certs-quic/certs/fullchain.pem")
    }

    fn get_server_key() -> &'static [u8] {
        include_bytes!("certs-quic/certs/server-key.pem")
    }

    fn get_ptr(mc: &mut Buffer) -> *mut c_void {
        mc as *mut Buffer as *mut c_void
    }

    // TODO: set lifetime expectations for read_buf and write_buf/make it so that read_buf and write_buf are always valid
    fn create_conn(
        mode: Mode,
        read_buf: &mut Pin<Box<Buffer>>,
        write_buf: &mut Pin<Box<Buffer>>,
    ) -> Connection {
        let read_ptr = Self::get_ptr(read_buf);
        let write_ptr = Self::get_ptr(write_buf);

        let mut builder = Builder::new();
        builder.set_security_policy(&DEFAULT_TLS13).unwrap();

        match mode {
            Mode::Server => builder
                .load_pem(Self::get_cert_chain(), Self::get_server_key())
                .unwrap(),
            Mode::Client => builder
                .trust_pem(Self::get_root_cert())
                .unwrap()
                .set_verify_host_callback(HostNameHandler {
                    hostname: "localhost",
                })
                .unwrap(),
        };

        let config = builder.build().unwrap();

        let mut conn = Connection::new(mode);

        conn.set_blinding(Blinding::SelfService)
            .unwrap()
            .set_config(config)
            .unwrap()
            .set_send_callback(Some(Self::send_cb))
            .unwrap()
            .set_receive_callback(Some(Self::recv_cb))
            .unwrap();
        unsafe {
            conn.set_send_context(write_ptr)
                .unwrap()
                .set_receive_context(read_ptr)
                .unwrap();
        }
        conn
    }
}

impl TlsImpl for S2nTls {
    fn handshake() {
        let mut c_to_s_buf = Box::pin(Buffer::new());
        let mut s_to_c_buf = Box::pin(Buffer::new());

        let mut server = Self::create_conn(Mode::Server, &mut c_to_s_buf, &mut s_to_c_buf);
        let mut client = Self::create_conn(Mode::Client, &mut s_to_c_buf, &mut c_to_s_buf);

        let mut max_iter = 100;
        let mut pending = true;
        while max_iter > 0 && pending {
            pending = false;
            println!("Client:");
            let client_res = client.poll_negotiate();
            if let Ready(res) = client_res {
                res.unwrap();
            } else {
                pending = true;
            }
            println!("Server:");
            let server_res = server.poll_negotiate();
            if let Ready(res) = server_res {
                res.unwrap();
            } else {
                pending = true;
            }
            max_iter -= 1;
        }
    }
}
