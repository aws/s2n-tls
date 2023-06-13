use std::{
    fs::read_to_string,
    io::{Read, Write},
};

// TODO: figure out why 2 round trips are happening
// TODO: use something other than Vec<u8> (BytesMut? VecDeque<Bytes>?)
// TODO: change visibilities of functions
// TODO: refactor to have common harness/add methods to custom harness
// TODO: add comments
// TODO: bulk transfer
// TODO: understand cert generate script/customize
// TODO: change rustls to tls1.3

pub fn read_to_bytes(path: &str) -> Vec<u8> {
    read_to_string(path).unwrap().into_bytes()
}

pub enum Mode {
    Client,
    Server,
}

pub trait TlsImpl {
    /// Initialize buffers, configs, and connections (unhandshaked)
    fn new() -> Self;

    /// Reinitialize connection with same configs
    fn reinit(&mut self);

    /// Process handshake for a single connection (i.e. client or server)
    fn handshake_conn(&mut self, mode: Mode);

    /// Run handshake on initialized connection
    fn handshake(&mut self) {
        // set limit on round trips
        let mut iter_remaining = 10;
        while !self.has_handshaked() && iter_remaining > 0 {
            self.handshake_conn(Mode::Client);
            self.handshake_conn(Mode::Server);
            iter_remaining -= 1;
        }
    }

    /// Checks if handshake is finished for both client and server
    fn has_handshaked(&self) -> bool;

    /// Send and receive data from each connection.
    /// If handshake hasn't happened yet, will handshake first
    fn bulk_transfer(&mut self, data: &mut [u8]);
}

/// Read+Write buffer used for custom IO for different TlsImpl
pub struct Buffer {
    pub bytes: Vec<u8>,
}

impl Buffer {
    pub fn new() -> Self {
        Buffer { bytes: Vec::new() }
    }
    pub fn clear(&mut self) -> &mut Self {
        self.bytes.clear();
        self
    }
    pub fn is_empty(&self) -> bool {
        return self.bytes.is_empty();
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
