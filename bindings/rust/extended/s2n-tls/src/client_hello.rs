// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Fallible};
use s2n_tls_sys::*;
use std::fmt;

// ClientHello is an opaque wrapper struct around `s2n_client_hello`. Note that
// the size of this type is not known, and as such it can only be used through
// references and pointers.
//
// This implementation is motivated by the different memory management required
// for different s2n_client_hello pointers. `s2n_client_hello_parse_message`
// returns a `*mut s2n_client_hello` which owns its own memory. This neatly fits
//  the "smart pointer" pattern and can be represented as a `Box<T>`.
//
// `s2n_connection_get_client_hello` returns a `*mut s2n_client_hello` which
// references memory owned by the connection, and therefore must not outlive
// the connection struct. This is best represented as a reference tied to the
// lifetime of the `Connection` struct.

pub struct ClientHello(s2n_client_hello);

impl ClientHello {
    pub fn parse_client_hello(hello: &[u8]) -> Result<Box<Self>, crate::error::Error> {
        crate::init::init();
        let handle = unsafe {
            s2n_client_hello_parse_message(hello.as_ptr(), hello.len() as u32).into_result()?
        };
        let client_hello = handle.as_ptr() as *mut ClientHello;
        // safety: s2n_client_hello_parse_message returns a pointer that "owns"
        // its memory. This memory must be cleaned up by the application. The
        // Box<Self> will call Self::Drop when it goes out of scope so memory
        // will be automatically managed.
        unsafe { Ok(Box::from_raw(client_hello)) }
    }

    // this accepts a mut ref instead of a pointer, so that lifetimes are nicely
    // calculated for us. As is always the case, the reference must not be null.
    // this is marked "pub(crate)" to expose it to the connection module but
    // prevent it from being used externally.
    pub(crate) fn from_ptr(hello: &s2n_client_hello) -> &Self {
        // SAFETY: casting *s2n_client_hello <-> *ClientHello: For repr(Rust),
        // repr(packed(N)), repr(align(N)), and repr(C) structs: if all fields of a
        // struct have size 0, then the struct has size 0.
        // https://rust-lang.github.io/unsafe-code-guidelines/layout/structs-and-tuples.html#zero-sized-structs
        unsafe { &*(hello as *const s2n_client_hello as *const ClientHello) }
    }

    // SAFETY: casting *const s2n_client_hello -> *mut s2n_client_hello: This is
    // safe as long as the data is not actually mutated. As authors of s2n-tls,
    // we know that the get_hash and get_fingerprint methods do not mutate the
    // data, and use mut pointers as a matter of convention because it makes
    // working with s2n_stuffers and s2n_blobs easier.
    pub(crate) fn deref_mut_ptr(&self) -> *mut s2n_client_hello {
        &self.0 as *const s2n_client_hello as *mut s2n_client_hello
    }

    pub fn session_id(&self) -> Result<Vec<u8>, Error> {
        let mut session_id_length = 0;
        unsafe {
            s2n_client_hello_get_session_id_length(self.deref_mut_ptr(), &mut session_id_length)
                .into_result()?;
        }

        let mut session_id = vec![0; session_id_length as usize];
        let mut out_length = 0;
        unsafe {
            s2n_client_hello_get_session_id(
                self.deref_mut_ptr(),
                session_id.as_mut_ptr(),
                &mut out_length,
                session_id_length,
            )
            .into_result()?;
        }
        Ok(session_id)
    }

    pub fn server_name(&self) -> Result<Vec<u8>, Error> {
        let mut server_name_length = 0;
        unsafe {
            s2n_client_hello_get_server_name_length(self.deref_mut_ptr(), &mut server_name_length)
                .into_result()?;
        }

        let mut server_name = vec![0; server_name_length as usize];
        let mut out_length = 0;
        unsafe {
            s2n_client_hello_get_server_name(
                self.deref_mut_ptr(),
                server_name.as_mut_ptr(),
                server_name_length,
                &mut out_length,
            )
            .into_result()?;
        }
        Ok(server_name)
    }

    pub fn raw_message(&self) -> Result<Vec<u8>, Error> {
        let message_length =
            unsafe { s2n_client_hello_get_raw_message_length(self.deref_mut_ptr()).into_result()? };

        let mut raw_message = vec![0; message_length];
        unsafe {
            s2n_client_hello_get_raw_message(
                self.deref_mut_ptr(),
                raw_message.as_mut_ptr(),
                message_length as u32,
            )
            .into_result()?
        };
        Ok(raw_message)
    }
}

impl Drop for ClientHello {
    fn drop(&mut self) {
        let mut client_hello: *mut s2n_client_hello = &mut self.0;
        // ignore failures. There isn't anything to be done to handle them, but
        // allowing the program to continue is preferable to crashing.
        let _ = unsafe {
            s2n_tls_sys::s2n_client_hello_free(std::ptr::addr_of_mut!(client_hello)).into_result()
        };
    }
}

impl fmt::Debug for ClientHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let session_id = self.session_id().map_err(|_| fmt::Error)?;
        let session_id = hex::encode(session_id);
        let message_head = self.raw_message().map_err(|_| fmt::Error)?;
        f.debug_struct("ClientHello")
            .field("session_id", &session_id)
            .field("message_len", &(message_head.len()))
            .finish_non_exhaustive()
    }
}

// Leftover from when fingerprinting was implemented in this module
#[cfg(feature = "unstable-fingerprint")]
pub use crate::fingerprint::FingerprintType;

#[cfg(test)]
mod tests {
    use crate::client_hello::ClientHello;

    #[test]
    fn invalid_client_bytes() {
        let raw_client_hello_bytes =
            "random_value_that_is_unlikely_to_be_valid_client_hello".as_bytes();
        let result = ClientHello::parse_client_hello(raw_client_hello_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn server_name() {
        let raw_client_hello = vec![
            0x01, 0x00, 0x00, 0xEC, 0x03, 0x03, 0x90, 0xe8, 0xcc, 0xee, 0xe5, 0x70, 0xa2, 0xa1,
            0x2f, 0x6b, 0x69, 0xd2, 0x66, 0x96, 0x0f, 0xcf, 0x20, 0xd5, 0x32, 0x6e, 0xc4, 0xb2,
            0x8c, 0xc7, 0xbd, 0x0a, 0x06, 0xc2, 0xa5, 0x14, 0xfc, 0x34, 0x20, 0xaf, 0x72, 0xbf,
            0x39, 0x99, 0xfb, 0x20, 0x70, 0xc3, 0x10, 0x83, 0x0c, 0xee, 0xfb, 0xfa, 0x72, 0xcc,
            0x5d, 0xa8, 0x99, 0xb4, 0xc5, 0x53, 0xd6, 0x3d, 0xa0, 0x53, 0x7a, 0x5c, 0xbc, 0xf5,
            0x0b, 0x00, 0x1e, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x2c, 0xc0,
            0x30, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x33, 0x00, 0x39, 0x00,
            0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x85, 0x00, 0x00, 0x00, 0x23, 0x00,
            0x21, 0x00, 0x00, 0x1e, 0x69, 0x6e, 0x63, 0x6f, 0x6d, 0x69, 0x6e, 0x67, 0x2e, 0x74,
            0x65, 0x6c, 0x65, 0x6d, 0x65, 0x74, 0x72, 0x79, 0x2e, 0x6d, 0x6f, 0x7a, 0x69, 0x6c,
            0x6c, 0x61, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
            0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e,
            0x31, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x18,
            0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
            0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01, 0x00, 0x1c, 0x00, 0x02,
            0x40, 0x00,
        ];
        let client_hello = ClientHello::parse_client_hello(raw_client_hello.as_slice()).unwrap();
        let server_name = client_hello.server_name().unwrap();
        assert_eq!("incoming.telemetry.mozilla.org".as_bytes(), server_name);
    }
}
