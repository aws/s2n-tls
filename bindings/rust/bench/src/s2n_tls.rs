use crate::TlsImpl;
use crate::harness::Buffer;
use s2n_tls::{
    callbacks::VerifyHostNameCallback,
    config::{Builder, Config},
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

// TODO: test if &mut [u8] autoimplements Read+Write
pub struct S2nTls {
    c_to_s_buf: Pin<Box<Buffer>>,
    s_to_c_buf: Pin<Box<Buffer>>,
    c_config: Config,
    s_config: Config,
    c_conn: Connection,
    s_conn: Connection
}

// TODO: use something other than Vec<u8> (BytesMut? VecDeque<Bytes>?)
// TODO: change visibilities of functions
// TODO: refactor to have common harness
// TODO: add comments

/// Custom callback for verifying hostnames, mandatory to use s2n-tls
pub struct HostNameHandler<'a> {
    hostname: &'a str,
}
impl VerifyHostNameCallback for HostNameHandler<'_> {
    fn verify_host_name(&self, hostname: &str) -> bool {
        self.hostname == hostname
    }
}

impl S2nTls  {
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
    
    fn create_config(mode: Mode) -> Config {
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

        builder.build().unwrap()
    }

    fn init_conn(&mut self, mode: Mode) {
        let teset = &mut self.c_to_s_buf;
        let c_to_s_ptr = Self::get_ptr(&mut self.c_to_s_buf);
        let s_to_c_ptr = Self::get_ptr(&mut self.s_to_c_buf);
        let (read_ptr, write_ptr, config, conn);
        match mode {
            Mode::Client => {
                read_ptr = s_to_c_ptr;
                write_ptr = c_to_s_ptr;
                config = &self.c_config;
                conn = &mut self.c_conn;
            }
            Mode::Server => {
                read_ptr = c_to_s_ptr;
                write_ptr = s_to_c_ptr;
                config = &self.s_config;
                conn = &mut self.s_conn;
            }
        }

        conn.set_blinding(Blinding::SelfService)
            .unwrap()
            .set_config(config.clone())
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
    }
}

impl TlsImpl for S2nTls {
    fn new() -> Self {
        let mut new_struct = S2nTls {
            c_to_s_buf: Box::pin(Buffer::new()),
            s_to_c_buf: Box::pin(Buffer::new()),
            c_config: Self::create_config(Mode::Client),
            s_config: Self::create_config(Mode::Server),
            c_conn: Connection::new_client(),
            s_conn: Connection::new_server(),
        };
        new_struct.init_conn(Mode::Client);
        new_struct.init_conn(Mode::Server);
        new_struct
    }

    fn handshake(&mut self) -> &mut Self {
        let mut max_iter = 100;
        let mut pending = true;
        while max_iter > 0 && pending {
            pending = false;
            println!("Client:");
            let client_res = self.s_conn.poll_negotiate();
            if let Ready(res) = client_res {
                res.unwrap();
            } else {
                pending = true;
            }
            println!("Server:");
            let server_res = self.c_conn.poll_negotiate();
            if let Ready(res) = server_res {
                res.unwrap();
            } else {
                pending = true;
            }
            max_iter -= 1;
        }
        self
    }
}
