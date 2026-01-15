// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module defines an "extension" trait to add our own bindings to the openssl
//! crate. Ideally all of this logic would live _in_ the openssl crate, but they
//! don't always accept PRs.

use openssl::ssl::{SslContextBuilder, SslRef, SslStream};
use openssl_sys::SSL_CTX;

extern "C" {
    /// ```c
    /// int SSL_CTX_set_block_padding(SSL_CTX *ctx, size_t block_size);
    /// ```
    pub fn SSL_CTX_set_block_padding(ctx: *mut SSL_CTX, block_size: usize) -> std::ffi::c_int;
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
