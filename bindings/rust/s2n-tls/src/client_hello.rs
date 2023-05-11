use std::ops::Deref;
use std::ops::DerefMut;

use s2n_tls_sys::*;

use crate::error::ErrorType;
use crate::error::Fallible;

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

/// ClientHello is an opaque wrapper struct around `s2n_client_hello`. Note that
/// the size of this type is not known, and as such it can only be used through
/// references and pointers.
///
/// This implementation is motivated by the different memory_management required
/// for different s2n_client_hello pointers. `s2n_client_hello_parse_message`
/// returns a `*mut s2n_client_hello` which owns it's own data. This neatly fits
///  the "smart pointer" pattern and can be represented as a `Box<T>`.
///
/// `s2n_connection_get_client_hello` returns a `*mut s2n_client_hello` which
/// references memory owned by the connection, and therefore must not outlive
/// the connection struct. This is best represented as a reference tied to the
/// lifetime of the `Connection` struct.

pub struct ClientHello(s2n_client_hello);

// safety justifications
// 1 - casting *s2n_client_hello <-> *ClientHello: a struct with only one field
// has the same layout as that field
// https://rust-lang.github.io/unsafe-code-guidelines/layout/structs-and-tuples.html#single-field-structs
// 2 - casting *const s2n_client_hello -> *mut s2n_client_hello: This is safe as
// long as the data is not actually mutated. As authors of s2n-tls, we know that
// the get_hash and get_fingerprint methods do not mutate the data, and use mut
// pointers as a matter of convention because it makes working with s2n_stuffers
// and s2n_blobs easier.

impl Deref for ClientHello {
    type Target = s2n_client_hello;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ClientHello {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ClientHello {
    // This is the initial "guess" at the fingerprint size. If someone only
    // wants to calculate the actual fingerprint, we don't want to have to
    // generate the JA3 fingerprint twice, so we make an educated guess at a
    // size that will work for most values. This value was chosen by looking
    //  through the "known test cases" in s2n_fingerprint_ja3_test and choosing
    // a power of two that worked for the values there.
    const INITIAL_FINGERPRINT_CAPACITY: u32 = 256;

    pub fn parse_client_hello(hello: &[u8]) -> Result<Box<Self>, crate::error::Error> {
        let handle = unsafe {
            s2n_client_hello_parse_message(hello.as_ptr(), hello.len() as u32).into_result()?
        };
        let client_hello = handle.as_ptr() as *mut ClientHello;
        // safety: s2n_client_hello_parse_message returns a pointer that "owns"
        // it's memory. This memory must be cleaned up by the application. The
        // Box<Self> will call Self::Drop when it goes out of scope so memory
        // will be automatically managed.
        unsafe { Ok(Box::from_raw(client_hello)) }
    }

    // this accepts a mut ref instead of a pointer, so that lifetimes are nicely
    // calculated for us. As is always the case, the reference must not be null
    pub fn from_ptr(hello: &s2n_client_hello) -> &Self {
        // safety: see safety justifications [1]
        unsafe { &*(hello as *const s2n_client_hello as *const ClientHello) }
    }

    pub fn fingerprint_hash(&self, hash: FingerprintType) -> Vec<u8> {
        let mut hash_result = vec![0; MD5_HASH_SIZE as usize];
        // safety justifications [2]
        let handle = self.deref() as *const s2n_client_hello as *mut s2n_client_hello;
        let mut hash_size: u32 = 0;
        let mut str_size: u32 = 0;
        unsafe {
            s2n_client_hello_get_fingerprint_hash(
                handle,
                hash.into(),
                MD5_HASH_SIZE,
                hash_result.as_mut_ptr(),
                &mut hash_size,
                &mut str_size,
            )
            .into_result()
            // get_fingerprint_hash is not expected to be fallible. A failure
            // implies a more exotic, non-recoverable error like OOM.
            .unwrap()
        };
        hash_result
    }

    pub fn fingerprint_string(&self, hash: FingerprintType) -> String {
        let mut capacity = Self::INITIAL_FINGERPRINT_CAPACITY;
        loop {
            // safety justifications [2]
            let handle = self.deref() as *const s2n_client_hello as *mut s2n_client_hello;
            let mut string: Vec<u8> = vec![0; capacity as usize];
            let mut output_size = 0;
            let result = unsafe {
                s2n_tls_sys::s2n_client_hello_get_fingerprint_string(
                    handle,
                    hash.into(),
                    capacity,
                    string.as_mut_ptr(),
                    &mut output_size,
                )
                .into_result()
            };

            // if the fingerprint failed because the buffer was too small,
            // double the buffer size and try again
            if let Err(s2n_error) = result {
                if s2n_error.kind() == ErrorType::UsageError {
                    capacity *= 2;
                } else {
                    // get_fingerprint_hash is not expected to be fallible for
                    // well structured input. A failure implies a more exotic,
                    // non-recoverable error like OOM.
                    panic!("{}", s2n_error);
                }
            } else {
                string.truncate(output_size as usize);
                // prefer "unwrap" over "from_utf8_unchecked" so that if we are
                // wrong we get a nice error message.
                return String::from_utf8(string).unwrap();
            }
        }
    }
}

impl Drop for ClientHello {
    fn drop(&mut self) {
        println!("doing a drop over here");
        let mut client_hello: *mut s2n_client_hello = self.deref_mut();
        // ignore failures. There isn't anything to be done to handle them, but
        // allowing the program to continue is preferable to crashing.
        let _ = unsafe {
            s2n_tls_sys::s2n_client_hello_free(std::ptr::addr_of_mut!(client_hello)).into_result()
        };
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        connection::Connection,
        error::Error,
        security,
        testing::{poll_tls_pair, s2n_tls::Harness, Pair},
    };

    use super::*;

    // makes sure that the get_fingerprint method properly catches the "too
    // small" error and can resize the buffer
    #[test]
    fn resizing_fingerprint_test() {
        todo!("implement a test with big fingerprint")
    }

    // test that fingerprints can successfully be calculated from ClientHellos
    // returned from a connection
    #[test]
    fn io_fingerprint_test() -> Result<(), Error> {
        let config = crate::testing::config_builder(&security::DEFAULT_TLS13)
            .unwrap()
            .build()?;

        let server = {
            // create and configure a server connection
            let mut server = crate::connection::Connection::new_server();
            server.set_config(config.clone())?;
            Harness::new(server)
        };

        let client = {
            // create a client connection
            let mut client = crate::connection::Connection::new_client();
            client.set_config(config)?;
            Harness::new(client)
        };

        // client_hellos can not be accessed before the handshake
        assert!(client.connection().client_hello().is_err());
        assert!(server.connection().client_hello().is_err());

        let pair = Pair::new(server, client);

        let pair = poll_tls_pair(pair);
        let server_conn = pair.server.0.connection();
        let client_conn = pair.server.0.connection();

        let check_client_hello = |conn: &Connection| {
            let expected_hash = "3d80a90bdfa45a3cee62cccfda33c885";
            let expected_fingerprint = "771,4865-4866-4867-49195-49199-49\
                                              196-49200-52393-52392-49161-49171\
                                              -49187-49191-49162-49172-156-60-4\
                                              7-255,43-10-51-13-11-23,29-23-24,0";

            let client_hello = conn.client_hello().unwrap();
            assert_eq!(
                hex::encode(client_hello.fingerprint_hash(FingerprintType::JA3)),
                expected_hash
            );
            assert_eq!(
                client_hello.fingerprint_string(FingerprintType::JA3),
                expected_fingerprint
            );
        };

        check_client_hello(server_conn);
        check_client_hello(client_conn);

        Ok(())
        //todo!("implement a test that uses a ClientHello from actual IO")
    }

    fn known_test_case(
        raw_client_hello: Vec<u8>,
        expected_fingerprint: &str,
        expected_hash_hex: &str,
    ) {
        let expected_hash: Vec<u8> = hex::decode(expected_hash_hex).unwrap();
        crate::init::init();
        let client_hello = ClientHello::parse_client_hello(raw_client_hello.as_slice()).unwrap();
        let hash = client_hello.fingerprint_hash(FingerprintType::JA3);
        assert_eq!(hash, expected_hash);

        let fingerprint = client_hello.fingerprint_string(FingerprintType::JA3);
        assert_eq!(&fingerprint, expected_fingerprint);
    }

    #[test]
    fn invalid_client_bytes() {
        let raw_client_hello_bytes = "random_value_that_is_unlikely_to_be_valid_client_hello".as_bytes();
        let result = ClientHello::parse_client_hello(raw_client_hello_bytes);
        assert!(result.is_err());
    }

    // known value test case copied from s2n_fingerprint_ja3_test.c
    #[test]
    fn valid_client_bytes() {
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
        let expected_fingerprint = "771,49195-49199-52393-52392-49196-49200-\
                                    49162-49161-49171-49172-51-57-47-53-10,0-\
                                    23-65281-10-11-35-16-5-13-28,29-23-24-25,0";
        let expected_hash_hex = "839bbe3ed07fed922ded5aaf714d6842";
        known_test_case(raw_client_hello, expected_fingerprint, expected_hash_hex);
    }
}
