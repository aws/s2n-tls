use std::io::{Read, Write};

// pub trait TlsImpl {
//     fn handshake();
// }

pub struct Buffer {
    pub bytes: Vec<u8>,
}

impl Buffer {
    pub fn new() -> Self {
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


pub trait TlsImpl {
    /// Initialize connection fully to be ready for handshake
    fn new() -> Self;

    /// Run handshake on initialized connection
    fn handshake(&mut self) -> &mut Self;
}
