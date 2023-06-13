use bench::{S2nTls, TlsImpl};
use simple_logger::SimpleLogger;

fn main() {
    SimpleLogger::new().init().unwrap();

    println!("\n----- s2n-tls handshake -----");
    let mut s2n = S2nTls::new();
    println!("HANDSHAKE");
    s2n.handshake();
    println!("HANDSHAKE DONE\n");
}
