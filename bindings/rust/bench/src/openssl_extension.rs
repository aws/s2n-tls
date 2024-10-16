//! This module defines "extension" trait to add our own bindings to the openssl
//! crate. Ideally all of this logic would live _in_ the openssl crate, but they
//! don't really accept PRs
//! - add signature type retrieval functions: https://github.com/sfackler/rust-openssl/pull/2164
//! - Add helper to return &mut SslRef from stream: https://github.com/sfackler/rust-openssl/pull/2223

// # define SSL_CTX_set_max_send_fragment(ctx,m) \
//         SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_SEND_FRAGMENT,m,NULL)

use std::ffi::c_long;

use openssl::ssl::SslContext;
use openssl_sys::SSL_CTX;

// very tediously, we need to import exactly the same verion of ForeignType as 
// ossl because we need this trait impl to access the raw pointers on all of the
// openssl types.
use foreign_types_shared::ForeignType;

// expose the macro as a function
fn SSL_CTX_set_max_send_fragment(ctx: *mut SSL_CTX, m: c_long) -> c_long {
        // # define SSL_CTRL_SET_MAX_SEND_FRAGMENT          52
        const SSL_CTRL_SET_MAX_SEND_FRAGMENT: std::ffi::c_int = 52;

        // TODO: assert on the return value
        unsafe {openssl_sys::SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_SEND_FRAGMENT, m, std::ptr::null_mut())} 
}

extern "C" {
    // int SSL_CTX_set_block_padding(SSL_CTX *ctx, size_t block_size);
    pub fn SSL_CTX_set_block_padding(ctx: *mut SSL_CTX, block_size: usize) -> std::ffi::c_int;
}

pub trait SslContextExtension {
    fn set_max_send_fragment(&mut self, max_send_fragment: usize);

    fn set_block_padding(&mut self, block_size: usize);
}

impl SslContextExtension for SslContext {
    fn set_max_send_fragment(&mut self, max_send_fragment: usize) {
        SSL_CTX_set_max_send_fragment(self.as_ptr(), max_send_fragment as _);
    }
    
    fn set_block_padding(&mut self, block_size: usize) {
        unsafe {SSL_CTX_set_block_padding(self.as_ptr(), block_size as _);}
    }
}
