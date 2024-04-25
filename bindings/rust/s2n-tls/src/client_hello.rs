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
    fn deref_mut_ptr(&self) -> *mut s2n_client_hello {
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

#[cfg(feature = "unstable-fingerprint")]
pub use self::fingerprint::*;

// Fingerprinting is an unstable feature. This module can be removed and added
// to the client_hello module once we have settled on an implementation.
#[cfg(feature = "unstable-fingerprint")]
pub mod fingerprint {
    use crate::error::{Error, Fallible};
    use s2n_tls_sys::*;

    use super::ClientHello;

    #[non_exhaustive]
    #[derive(Copy, Clone)]
    pub enum FingerprintType {
        JA3,
    }

    // this is the size of the MD5 hash digest that is used for the JA3 fingerprint
    const MD5_HASH_SIZE: u32 = 16;

    impl From<FingerprintType> for s2n_tls_sys::s2n_fingerprint_type::Type {
        fn from(value: FingerprintType) -> Self {
            match value {
                FingerprintType::JA3 => s2n_tls_sys::s2n_fingerprint_type::FINGERPRINT_JA3,
            }
        }
    }

    impl ClientHello {
        /// `fingerprint_hash` calculates the hash, and also returns the size
        /// required for the full fingerprint string. The return value can be used
        /// to construct a string of appropriate capacity to call
        /// `fingerprint_string`. `output` will be extended if necessary to store
        /// the full hash.
        ///
        /// ```no_run
        /// use s2n_tls::client_hello::{ClientHello, FingerprintType};
        /// use s2n_tls::connection::Connection;
        /// use s2n_tls::enums::Mode;
        ///
        /// let mut conn = Connection::new(Mode::Server);
        /// // handshake happens
        /// let mut client_hello: &ClientHello = conn.client_hello().unwrap();
        /// let mut hash = Vec::new();
        /// let string_size = client_hello.fingerprint_hash(FingerprintType::JA3, &mut hash).unwrap();
        /// // hash has been resized so that it can store the fingerprint hash
        ///
        /// let mut string = String::with_capacity(string_size as usize);
        /// // string will not be resized, and the method will fail with
        /// // ErrorType::UsageError if the string doesn't have enough capacity
        /// client_hello.fingerprint_string(FingerprintType::JA3, &mut string).unwrap();
        /// ```
        pub fn fingerprint_hash(
            &self,
            hash: FingerprintType,
            output: &mut Vec<u8>,
        ) -> Result<u32, Error> {
            let mut hash_size: u32 = 0;
            let mut str_size: u32 = 0;
            // make sure the vec has sufficient space for the hash
            if output.capacity() < MD5_HASH_SIZE as usize {
                output.reserve_exact(MD5_HASH_SIZE as usize - output.len());
            }
            unsafe {
                s2n_client_hello_get_fingerprint_hash(
                    self.deref_mut_ptr(),
                    hash.into(),
                    MD5_HASH_SIZE,
                    output.as_mut_ptr(),
                    &mut hash_size,
                    &mut str_size,
                )
                .into_result()?;
                // SAFETY: we wrote to the raw vec (using the mut pointer), and need
                // to update the state of the vec to reflect the changes we made.
                output.set_len(hash_size as usize);
            };
            Ok(str_size)
        }

        /// `fingerprint_string` will try to calculate the fingerprint and store the
        /// resulting string in `output`. If `output` does not have sufficient
        /// capacity an Error of `ErrorType::UsageError` will be returned.
        pub fn fingerprint_string(
            &self,
            hash: FingerprintType,
            output: &mut String,
        ) -> Result<(), Error> {
            let mut output_size = 0;
            unsafe {
                s2n_tls_sys::s2n_client_hello_get_fingerprint_string(
                    self.deref_mut_ptr(),
                    hash.into(),
                    output.capacity() as u32,
                    output.as_mut_ptr(),
                    &mut output_size,
                )
                .into_result()?;
                // SAFETY: update internal state of string to match the data written
                // into it.
                output.as_mut_vec().set_len(output_size as usize);
            };
            Ok(())
        }
    }

    #[cfg(test)]
    pub mod fingerprint_tests {
        use crate::{
            client_hello::{
                fingerprint::{FingerprintType, MD5_HASH_SIZE},
                ClientHello,
            },
            connection::Connection,
            error::{Error, ErrorType},
            security,
            testing::{poll_tls_pair, tls_pair},
        };

        /// This function is a test fixture used a generate a valid ClientHello so
        /// that we don't have to copy and paste the raw bytes for test fixtures
        fn get_client_hello_bytes() -> Vec<u8> {
            let config = crate::testing::config_builder(&security::DEFAULT_TLS13)
                .unwrap()
                .build()
                .unwrap();
            let pair = tls_pair(config);
            let pair = poll_tls_pair(pair);
            // this doesn't have the handshake header
            let client_hello_message = pair
                .server
                .0
                .connection()
                .client_hello()
                .unwrap()
                .raw_message()
                .unwrap();
            // handshake header is {tag: u8, client_hello_length: u24}
            let mut client_hello = vec![0; 4];
            // As long as the client hello is small, no bit fiddling is required
            assert!(client_hello_message.len() < u8::MAX as usize);
            // tag for handshake header
            client_hello[0] = 1;
            client_hello[3] = client_hello_message.len() as u8;
            client_hello.extend(client_hello_message.iter());
            client_hello
        }

        fn known_test_case(
            raw_client_hello: Vec<u8>,
            expected_string: &str,
            expected_hash_hex: &str,
        ) -> Result<(), Error> {
            let expected_hash: Vec<u8> = hex::decode(expected_hash_hex).unwrap();
            let client_hello =
                ClientHello::parse_client_hello(raw_client_hello.as_slice()).unwrap();

            let mut hash = Vec::new();
            let string_size = client_hello
                .fingerprint_hash(FingerprintType::JA3, &mut hash)
                .unwrap();
            assert_eq!(hash, expected_hash);

            let mut string = String::with_capacity(string_size as usize);
            client_hello
                .fingerprint_string(FingerprintType::JA3, &mut string)
                .unwrap();
            assert_eq!(string, expected_string);
            Ok(())
        }

        pub fn get_client_hello() -> Box<ClientHello> {
            // sets up connection and handshakes
            let raw_client_hello = get_client_hello_bytes();
            ClientHello::parse_client_hello(raw_client_hello.as_slice()).unwrap()
        }

        pub fn client_hello_bytes() -> Vec<u8> {
            vec![
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
            ]
        }

        // test that a fingerprint can successfully be calculated from ClientHellos
        // returned from a connection
        #[checkers::test]
        fn io_fingerprint_test() {
            let config = crate::testing::config_builder(&security::DEFAULT_TLS13)
                .unwrap()
                .build()
                .unwrap();
            let pair = crate::testing::tls_pair(config);

            // client_hellos can not be accessed before the handshake
            assert!(pair.client.0.connection().client_hello().is_err());
            assert!(pair.server.0.connection().client_hello().is_err());

            let pair = poll_tls_pair(pair);
            let server_conn = pair.server.0.connection();
            let client_conn = pair.server.0.connection();

            let check_client_hello = |conn: &Connection| -> Result<(), Error> {
                let client_hello = conn.client_hello().unwrap();
                let mut hash = Vec::new();
                let fingerprint_size =
                    client_hello.fingerprint_hash(FingerprintType::JA3, &mut hash)?;
                let mut string = String::with_capacity(fingerprint_size as usize);
                client_hello.fingerprint_string(FingerprintType::JA3, &mut string)?;
                Ok(())
            };

            assert!(check_client_hello(server_conn).is_ok());
            assert!(check_client_hello(client_conn).is_ok());
        }

        // known value test case copied from s2n_fingerprint_ja3_test.c
        #[checkers::test]
        fn valid_client_bytes() {
            let raw_client_hello = client_hello_bytes();
            let expected_fingerprint = "771,49195-49199-52393-52392-49196-49200-\
                                        49162-49161-49171-49172-51-57-47-53-10,0-\
                                        23-65281-10-11-35-16-5-13-28,29-23-24-25,0";
            let expected_hash_hex = "839bbe3ed07fed922ded5aaf714d6842";
            known_test_case(raw_client_hello, expected_fingerprint, expected_hash_hex).unwrap();
        }

        #[test]
        fn hash_output_resizing() {
            let client_hello = get_client_hello();
            let hash_capacities = vec![0, MD5_HASH_SIZE, 1_000];
            for initial_size in hash_capacities {
                let mut hash = Vec::with_capacity(initial_size as usize);
                client_hello
                    .fingerprint_hash(FingerprintType::JA3, &mut hash)
                    .unwrap();
                assert_eq!(hash.len(), MD5_HASH_SIZE as usize);
            }
        }

        #[test]
        fn string_output_too_small() {
            let client_hello = get_client_hello();
            let mut fingerprint_string = String::with_capacity(0);
            let fingerprint_err = client_hello
                .fingerprint_string(FingerprintType::JA3, &mut fingerprint_string)
                .unwrap_err();
            assert_eq!(fingerprint_err.kind(), ErrorType::UsageError);
        }
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
