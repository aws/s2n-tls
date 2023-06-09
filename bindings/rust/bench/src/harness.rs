// use std::io::{Read, Write};

pub trait TlsImpl {
    fn handshake();
}

// pub trait TlsImpl {
//     /// Initialize connection fully to be ready for handshake
//     fn new_defaults() -> Self;

//     /// Get bare object
//     fn new() -> Self;

//     /// Set a read+write buffer to use
//     fn with_buffer<T: Read + Write>(&mut self, c_to_s: T, s_to_t: T) -> &mut Self;

//     /// Set up the relevant configs internally
//     fn init_config(&mut self) -> &mut Self;

//     /// Create the client and server connections internally
//     fn init_conn(&mut self) -> &mut Self;

//     fn handshake(&mut self) -> &mut Self;
// }
