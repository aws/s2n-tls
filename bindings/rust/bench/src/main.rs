use bench::{Rustls, S2nTls, TlsImpl};

// TODO: make common harness better
// TODO: add comments
// TODO: understand cert generate script/customize
fn main() {
    println!("----- rustls handshake -----");
    let mut rustls = Rustls::new();
    rustls.handshake();
    println!("\n----- s2n-tls handshake -----");
    let mut s2n = S2nTls::new();
    s2n.handshake();
}
