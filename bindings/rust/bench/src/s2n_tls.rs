use crate::{
    harness::{Buffer, Mode, TlsImpl},
    read_to_bytes, CA_CERT_PATH, SERVER_CERT_CHAIN_PATH, SERVER_KEY_PATH,
};
use log::info;
use s2n_tls::{
    callbacks::VerifyHostNameCallback,
    config::{Builder, Config},
    connection::Connection,
    enums::Blinding,
    security::DEFAULT_TLS13,
};
use std::{
    ffi::c_void,
    io::{Read, Write},
    os::raw::c_int,
    pin::Pin,
    task::Poll::Ready,
};

pub struct S2nTls {
    c_to_s_buf: Pin<Box<Buffer>>, // need Pin to make sure C pointer to Buffer doesn't move
    s_to_c_buf: Pin<Box<Buffer>>, // Buffer used in custom IO as context
    c_config: Config,
    s_config: Config,
    c_conn: Connection,
    s_conn: Connection,
    c_handshaked: bool,
    s_handshaked: bool,
}

/// Custom callback for verifying hostnames, need it to use s2n-tls safely
struct HostNameHandler<'a> {
    hostname: &'a str,
}
impl VerifyHostNameCallback for HostNameHandler<'_> {
    fn verify_host_name(&self, hostname: &str) -> bool {
        self.hostname == hostname
    }
}

impl S2nTls {
    /// Unsafe callback for custom IO C API
    unsafe extern "C" fn send_cb(context: *mut c_void, data: *const u8, len: u32) -> c_int {
        let context = &mut *(context as *mut Buffer);
        let data = core::slice::from_raw_parts(data, len as _);
        let ans = context.write(data).unwrap() as _;
        ans
    }

    /// Unsafe callback for custom IO C API
    unsafe extern "C" fn recv_cb(context: *mut c_void, data: *mut u8, len: u32) -> c_int {
        let context = &mut *(context as *mut Buffer);
        let mut data = core::slice::from_raw_parts_mut(data, len as _);
        context.flush().unwrap();
        let len = context.read(&mut data).unwrap();
        if len == 0 {
            info!("\t[blocking]");
            errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
            -1
        } else {
            info!("\t- received {len}");
            len as _
        }
    }

    fn create_config(mode: Mode) -> Config {
        let mut builder = Builder::new();
        builder.set_security_policy(&DEFAULT_TLS13).unwrap();

        match mode {
            Mode::Server => builder
                .load_pem(
                    read_to_bytes(SERVER_CERT_CHAIN_PATH).as_slice(),
                    read_to_bytes(SERVER_KEY_PATH).as_slice(),
                )
                .unwrap(),
            Mode::Client => builder
                .trust_pem(read_to_bytes(CA_CERT_PATH).as_slice())
                .unwrap()
                .set_verify_host_callback(HostNameHandler {
                    hostname: "localhost",
                })
                .unwrap(),
        };

        builder.build().unwrap()
    }

    /// Set up connections with config and custom IO
    fn init_conn(&mut self, mode: Mode) {
        let c_to_s_ptr = &mut self.c_to_s_buf as &mut Buffer as *mut Buffer as *mut c_void;
        let s_to_c_ptr = &mut self.s_to_c_buf as &mut Buffer as *mut Buffer as *mut c_void;
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

        conn.set_blinding(Blinding::SelfService) // no blinding so benchmark time is accurate
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

    /// Handshake step for one connection
    fn handshake_conn(&mut self, mode: Mode) {
        let (conn, handshaked);
        match mode {
            Mode::Client => {
                info!("Client: ");
                conn = &mut self.c_conn;
                handshaked = &mut self.c_handshaked;
            }
            Mode::Server => {
                info!("Server: ");
                conn = &mut self.s_conn;
                handshaked = &mut self.s_handshaked;
            }
        }
        if let Ready(res) = conn.poll_negotiate() {
            res.unwrap();
            *handshaked = true;
        } else {
            *handshaked = false;
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
            c_handshaked: false,
            s_handshaked: false,
        };
        new_struct.init_conn(Mode::Client);
        new_struct.init_conn(Mode::Server);
        new_struct
    }



    fn handshake(&mut self) {
        // set limit on round trips
        let mut iter_remaining = 10;
        while !self.has_handshaked() && iter_remaining > 0 {
            self.handshake_conn(Mode::Client);
            self.handshake_conn(Mode::Server);
            iter_remaining -= 1;
        }
    }


    fn has_handshaked(&self) -> bool {
        self.c_handshaked && self.s_handshaked
    }
}
