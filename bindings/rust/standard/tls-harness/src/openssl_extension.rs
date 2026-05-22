// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module defines an "extension" trait to add our own bindings to the openssl
//! crate. Ideally all of this logic would live _in_ the openssl crate, but they
//! don't always accept PRs.

use openssl::ssl::{SslContextBuilder, SslRef, SslStream};
use openssl_sys::SSL_CTX;

use foreign_types_shared::ForeignTypeRef;

fn ssl_get_secure_renegotiation_support(ssl: *mut openssl_sys::SSL) -> std::ffi::c_long {
    const SSL_CTRL_GET_RI_SUPPORT: std::ffi::c_int = 76;
    unsafe { openssl_sys::SSL_ctrl(ssl, SSL_CTRL_GET_RI_SUPPORT, 0, std::ptr::null_mut()) }
}
extern "C" {
    /// ```c
    /// int SSL_CTX_set_block_padding(SSL_CTX *ctx, size_t block_size);
    /// ```
    pub fn SSL_CTX_set_block_padding(ctx: *mut SSL_CTX, block_size: usize) -> std::ffi::c_int;

    pub fn SSL_renegotiate_pending(ssl: *mut openssl_sys::SSL) -> std::ffi::c_int;
    pub fn SSL_renegotiate(ssl: *mut openssl_sys::SSL) -> std::ffi::c_int;
}

pub trait SslContextExtension {
    fn set_block_padding(&mut self, block_size: usize);
}

impl SslContextExtension for SslContextBuilder {
    fn set_block_padding(&mut self, block_size: usize) {
        unsafe {
            // > The SSL_CTX_set_block_padding() and SSL_set_block_padding() functions
            // > return 1 on success or 0 if block_size is too large.
            // > https://docs.openssl.org/master/man3/SSL_CTX_set_record_padding_callback
            let res = SSL_CTX_set_block_padding(self.as_ptr(), block_size as _);
            assert_eq!(res, 1);
        }
    }
}

pub trait SslStreamExtension {
    fn mut_ssl(&mut self) -> &mut SslRef;
}

impl<T> SslStreamExtension for SslStream<T> {
    /// Required to obtain a mutable `SslRef` from `SslStream` for test-only
    /// logic. The cast is safe under our usage and tracked by an
    /// upstream PR: https://github.com/sfackler/rust-openssl/pull/2223
    #[allow(invalid_reference_casting)]
    fn mut_ssl(&mut self) -> &mut SslRef {
        unsafe { &mut *(self.ssl() as *const openssl::ssl::SslRef as *mut openssl::ssl::SslRef) }
    }
}

pub trait SslExtension {
    /// Returns `true` if the peer is patched against insecure renegotiation.
    fn secure_renegotiation_support(&self) -> bool;

    fn renegotiate_pending(&self) -> bool;

    /// Schedule a renegotiate request to be sent on the next io.
    fn renegotiate(&mut self);
}

impl SslExtension for openssl::ssl::SslRef {
    fn secure_renegotiation_support(&self) -> bool {
        let result = ssl_get_secure_renegotiation_support(self.as_ptr());
        match result {
            1 => true,
            0 => false,
            _ => unreachable!("unexpected OpenSSL return value; expected 0 or 1"),
        }
    }

    fn renegotiate_pending(&self) -> bool {
        match unsafe { SSL_renegotiate_pending(self.as_ptr()) } {
            1 => true,
            0 => false,
            _ => unreachable!("unexpected OpenSSL return value; expected 0 or 1"),
        }
    }

    fn renegotiate(&mut self) {
        // https://docs.openssl.org/3.3/man3/SSL_key_update/#return-values
        let result = unsafe { SSL_renegotiate(self.as_ptr()) };
        assert_eq!(result, 1);
    }
}
