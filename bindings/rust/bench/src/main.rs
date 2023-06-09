use bench::{Rustls, S2nTls, TlsImpl};

// TODO: make common harness better
// TODO: add comments
// TODO: understand cert generate script/customize
fn main() {
    println!("----- rustls handshake -----");
    Rustls::handshake();
    println!("\n----- s2n-tls handshake -----");
    S2nTls::handshake();
}
