use crate::{
    harness::{Buffer, Mode, TlsImpl},
    CA_CERT_PATH, SERVER_CERT_CHAIN_PATH, SERVER_KEY_PATH,
};
use log::info;
use openssl::ssl::{
    ErrorCode, Ssl, SslAcceptor, SslConnector, SslContext, SslFiletype, SslMethod, SslStream,
    SslVersion,
};
use std::{
    cell::RefCell,
    io::{Read, Write},
    rc::Rc,
};

pub struct OpenSsl {
    c_to_s_buf: Rc<RefCell<Buffer>>,
    s_to_c_buf: Rc<RefCell<Buffer>>,
    c_config: SslContext,
    s_config: SslContext,
    c_conn: SslStream<ConnectedBuffer>,
    s_conn: SslStream<ConnectedBuffer>,
}

impl TlsImpl for OpenSsl {
    fn new() -> Self {
        let c_to_s_buf = Rc::new(RefCell::new(Buffer::new()));
        let s_to_c_buf = Rc::new(RefCell::new(Buffer::new()));

        let mut c_builder = SslConnector::builder(SslMethod::tls()).unwrap();
        c_builder.set_ca_file(CA_CERT_PATH).unwrap();
        c_builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();

        let mut s_builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls()).unwrap();
        s_builder
            .set_certificate_chain_file(SERVER_CERT_CHAIN_PATH)
            .unwrap();
        s_builder
            .set_private_key_file(SERVER_KEY_PATH, SslFiletype::PEM)
            .unwrap();
        s_builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();

        let c_config = c_builder.build().into_context();
        let s_config = s_builder.build().into_context();

        let c_buf = ConnectedBuffer::new(s_to_c_buf.clone(), c_to_s_buf.clone());
        let s_buf = ConnectedBuffer::new(c_to_s_buf.clone(), s_to_c_buf.clone());

        let c_conn = SslStream::new(Ssl::new(&c_config).unwrap(), c_buf).unwrap();
        let s_conn = SslStream::new(Ssl::new(&s_config).unwrap(), s_buf).unwrap();

        OpenSsl {
            c_to_s_buf,
            s_to_c_buf,
            c_config,
            s_config,
            c_conn,
            s_conn,
        }
    }

    fn reinit(&mut self) {
        self.c_to_s_buf.borrow_mut().clear();
        self.s_to_c_buf.borrow_mut().clear();

        let c_buf = ConnectedBuffer::new(self.s_to_c_buf.clone(), self.c_to_s_buf.clone());
        let s_buf = ConnectedBuffer::new(self.c_to_s_buf.clone(), self.s_to_c_buf.clone());

        self.c_conn = SslStream::new(Ssl::new(&self.c_config).unwrap(), c_buf).unwrap();
        self.s_conn = SslStream::new(Ssl::new(&self.s_config).unwrap(), s_buf).unwrap();
    }

    fn handshake_conn(&mut self, mode: Mode) {
        let res;
        match mode {
            Mode::Client => {
                info!("Client: ");
                res = self.c_conn.connect();
            }
            Mode::Server => {
                info!("Server: ");
                res = self.s_conn.accept();
            }
        }
        match res {
            Ok(_) => {
                info!("\t[success]");
            }
            Err(err) => {
                if err.code() == ErrorCode::WANT_READ {
                    info!("\t[blocking]");
                } else {
                    panic!("{err:?}");
                }
            }
        }
    }

    fn has_handshaked(&self) -> bool {
        self.c_conn.ssl().is_init_finished() && self.s_conn.ssl().is_init_finished()
    }

    fn bulk_transfer(&mut self, _data: &mut [u8]) {
        if !self.has_handshaked() {
            self.handshake();
        }
    }
}

/// Wrapper of two shared buffers to pass as stream into openssl
struct ConnectedBuffer {
    recv: Rc<RefCell<Buffer>>,
    send: Rc<RefCell<Buffer>>,
}

impl<'a> ConnectedBuffer {
    pub fn new(recv: Rc<RefCell<Buffer>>, send: Rc<RefCell<Buffer>>) -> Self {
        ConnectedBuffer { recv, send }
    }
}

impl Read for ConnectedBuffer {
    fn read(&mut self, dest: &mut [u8]) -> Result<usize, std::io::Error> {
        match self.recv.borrow_mut().read(dest) {
            Ok(len) => {
                info!("\t- received {}", len);
                if len > 0 {
                    Ok(len)
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "bad"))
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl Write for ConnectedBuffer {
    fn write(&mut self, src: &[u8]) -> Result<usize, std::io::Error> {
        match self.send.borrow_mut().write(src) {
            Ok(len) => {
                info!("\t+ sent {}", len);
                Ok(len)
            }
            Err(err) => Err(err),
        }
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}
