use bench::{OpenSsl, Rustls, S2nTls, TlsImpl};
use simple_logger::SimpleLogger;

fn main() {
    SimpleLogger::new().init().unwrap();

    println!("----- rustls -----");
    let mut rustls = Rustls::new();
    println!("HANDSHAKE");
    rustls.handshake();
    println!("HANDSHAKE DONE\n");
    println!("BULK TRANSFER");
    rustls.bulk_transfer(&mut [0x38u8; 10000]);
    println!("BULK TRANSFER DONE");

    println!("\n----- s2n-tls handshake -----");
    let mut s2n = S2nTls::new();
    println!("HANDSHAKE");
    s2n.handshake();
    println!("HANDSHAKE DONE\n");
    println!("BULK TRANSFER");
    s2n.bulk_transfer(&mut [0x38u8; 10000]);
    println!("BULK TRANSFER DONE");

    println!("\n----- openssl handshake -----");
    let mut openssl = OpenSsl::new();
    println!("HANDSHAKE");
    openssl.handshake();
    println!("HANDSHAKE DONE\n");
    println!("BULK TRANSFER");
    openssl.bulk_transfer(&mut [0x38u8; 10000]);
    println!("BULK TRANSFER DONE");
}
