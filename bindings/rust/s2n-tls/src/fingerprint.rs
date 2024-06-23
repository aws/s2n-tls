// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Methods to fingerprint ClientHellos.
//!
//! See [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/fingerprint.h).

use crate::{
    client_hello::ClientHello,
    error::{Error, Fallible},
    ffi::*,
};

use core::ptr::NonNull;

#[non_exhaustive]
#[derive(Copy, Clone)]
pub enum FingerprintType {
    JA3,
}

const MD5_HASH_SIZE: u32 = 16;

impl From<FingerprintType> for s2n_tls_sys::s2n_fingerprint_type::Type {
    fn from(value: FingerprintType) -> Self {
        match value {
            FingerprintType::JA3 => s2n_tls_sys::s2n_fingerprint_type::FINGERPRINT_JA3,
        }
    }
}

/// A fingerprint operation.
pub struct Fingerprint<'a>(&'a mut NonNull<s2n_fingerprint>);

impl Fingerprint<'_> {
    /// Size of the fingerprint hash.
    /// See s2n_fingerprint_get_hash_size in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/fingerprint.h).
    pub fn hash_size(&self) -> Result<u32, Error> {
        let mut hash_size = 0;
        unsafe { s2n_fingerprint_get_hash_size(self.0.as_ptr(), &mut hash_size).into_result() }?;
        Ok(hash_size)
    }

    /// Calculate the fingerprint hash as a hex string.
    /// See s2n_fingerprint_get_hash in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/fingerprint.h).
    pub fn hash(&mut self, hash_hex: &mut String) -> Result<u32, Error> {
        let max_size: u32 = hash_hex
            .capacity()
            .try_into()
            .map_err(|_| Error::INVALID_INPUT)?;
        let mut output_size = 0;
        unsafe {
            s2n_fingerprint_get_hash(
                self.0.as_ptr(),
                max_size,
                hash_hex.as_mut_ptr(),
                &mut output_size,
            )
            .into_result()?;

            // SAFETY: update internal state of string to match the data written
            // into it.
            hash_hex.as_mut_vec().set_len(output_size as usize);
        };
        Ok(output_size)
    }

    /// Size of the raw fingerprint string.
    /// The size of the raw fingerprint string can't be known without calculating
    /// the fingerprint, so either [Fingerprint::hash()] or [Fingerprint::raw()]
    /// must be called before this method.
    ///
    /// See s2n_fingerprint_get_raw_size in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/fingerprint.h).
    pub fn raw_size(&self) -> Result<u32, Error> {
        let mut raw_size = 0;
        unsafe { s2n_fingerprint_get_raw_size(self.0.as_ptr(), &mut raw_size).into_result() }?;
        Ok(raw_size)
    }

    /// Calculate the raw fingerprint string.
    /// See s2n_fingerprint_get_raw in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/fingerprint.h).
    pub fn raw(&mut self, raw: &mut String) -> Result<u32, Error> {
        let max_size: u32 = raw
            .capacity()
            .try_into()
            .map_err(|_| Error::INVALID_INPUT)?;
        let mut output_size = 0;
        unsafe {
            s2n_fingerprint_get_raw(
                self.0.as_ptr(),
                max_size,
                raw.as_mut_ptr(),
                &mut output_size,
            )
            .into_result()?;

            // SAFETY: update internal state of string to match the data written
            // into it.
            raw.as_mut_vec().set_len(output_size as usize);
        };
        Ok(output_size)
    }

    pub fn builder(method: FingerprintType) -> Result<Builder, Error> {
        Builder::new(method)
    }
}

impl Drop for Fingerprint<'_> {
    /// Resets the underlying [Builder] for the next fingerprint.
    fn drop(&mut self) {
        unsafe {
            s2n_fingerprint_reset(self.0.as_ptr())
                .into_result()
                .unwrap()
        };
    }
}

/// Builder that can be reused for multiple fingerprints.
///
/// The `Builder` can build a new [Fingerprint] as soon as the old [Fingerprint]
/// goes out of scope. The [Fingerprint] implementation of [`Self::drop()`] ensures that this
/// is safe by reseting the underlying C structure.
///
/// See the below example:
/// ```no_run
/// use s2n_tls::client_hello::ClientHello;
/// use s2n_tls::fingerprint::{Fingerprint, FingerprintType};
///
/// let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
/// let client_hello_bytes = [ 0, 1, 2, 3, 4, 5 ];
///     
/// for _ in 1..10 {
///     let client_hello = ClientHello::parse_client_hello(&client_hello_bytes)?;
///     let mut fingerprint = builder.build(&client_hello)?;
///
///     let hash_size = fingerprint.hash_size()?;
///     let mut hash = String::with_capacity(hash_size as usize);
///     fingerprint.hash(&mut hash)?;
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// Multiple Fingerprints constructed from the same Builder can't exist simultaneously.
/// The below example fails to compile:
/// ```compile_fail,E0499
/// use s2n_tls::client_hello::ClientHello;
/// use s2n_tls::fingerprint::{Fingerprint, FingerprintType};
///
/// let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
///
/// let client_hello_bytes = [ 0, 1, 2, 3, 4, 5 ];
/// let client_hello_1 = ClientHello::parse_client_hello(&client_hello_bytes)?;
/// let client_hello_2 = ClientHello::parse_client_hello(&client_hello_bytes)?;
///
/// let mut fingerprint_1 = builder.build(&client_hello_1)?;
/// let mut fingerprint_2 = builder.build(&client_hello_2)?;
///
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct Builder(NonNull<s2n_fingerprint>);

impl Builder {
    /// Creates a reusable [Builder].
    pub fn new(method: FingerprintType) -> Result<Self, Error> {
        crate::init::init();
        let ptr = unsafe { s2n_fingerprint_new(method.into()).into_result() }?;
        Ok(Builder(ptr))
    }

    /// Creates a fingerprint operation for a given [ClientHello].
    pub fn build(&mut self, client_hello: &ClientHello) -> Result<Fingerprint, Error> {
        unsafe {
            s2n_fingerprint_set_client_hello(self.0.as_ptr(), client_hello.deref_mut_ptr())
                .into_result()
        }?;
        Ok(Fingerprint(&mut self.0))
    }
}

impl Drop for Builder {
    /// Frees the memory associated with this [Builder].
    fn drop(&mut self) {
        let mut ptr: *mut s2n_fingerprint = unsafe { self.0.as_mut() };
        unsafe {
            s2n_fingerprint_free(std::ptr::addr_of_mut!(ptr))
                .into_result()
                .unwrap()
        };
    }
}

// Legacy versions of the fingerprinting methods
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
mod tests {
    use super::*;
    use crate::{
        config,
        error::ErrorType,
        testing::{CertKeyPair, TestPair},
    };
    use std::error::Error;

    const CLIENT_HELLO_BYTES: &'static [u8] = &[
        0x01, 0x00, 0x00, 0xEC, 0x03, 0x03, 0x90, 0xe8, 0xcc, 0xee, 0xe5, 0x70, 0xa2, 0xa1, 0x2f,
        0x6b, 0x69, 0xd2, 0x66, 0x96, 0x0f, 0xcf, 0x20, 0xd5, 0x32, 0x6e, 0xc4, 0xb2, 0x8c, 0xc7,
        0xbd, 0x0a, 0x06, 0xc2, 0xa5, 0x14, 0xfc, 0x34, 0x20, 0xaf, 0x72, 0xbf, 0x39, 0x99, 0xfb,
        0x20, 0x70, 0xc3, 0x10, 0x83, 0x0c, 0xee, 0xfb, 0xfa, 0x72, 0xcc, 0x5d, 0xa8, 0x99, 0xb4,
        0xc5, 0x53, 0xd6, 0x3d, 0xa0, 0x53, 0x7a, 0x5c, 0xbc, 0xf5, 0x0b, 0x00, 0x1e, 0xc0, 0x2b,
        0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x2c, 0xc0, 0x30, 0xc0, 0x0a, 0xc0, 0x09, 0xc0,
        0x13, 0xc0, 0x14, 0x00, 0x33, 0x00, 0x39, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01, 0x00,
        0x00, 0x85, 0x00, 0x00, 0x00, 0x23, 0x00, 0x21, 0x00, 0x00, 0x1e, 0x69, 0x6e, 0x63, 0x6f,
        0x6d, 0x69, 0x6e, 0x67, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x74, 0x72, 0x79, 0x2e,
        0x6d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x17, 0x00, 0x00,
        0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17,
        0x00, 0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31,
        0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x18,
        0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04,
        0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x00,
    ];
    const JA3_FULL_STRING: &str = "771,49195-49199-52393-52392-49196-49200-\
                             49162-49161-49171-49172-51-57-47-53-10,0-\
                             23-65281-10-11-35-16-5-13-28,29-23-24-25,0";
    const JA3_HASH: &str = "839bbe3ed07fed922ded5aaf714d6842";

    fn simple_handshake() -> Result<TestPair, Box<dyn Error>> {
        let keypair = CertKeyPair::default();
        let mut config_builder = config::Builder::new();
        unsafe { config_builder.disable_x509_verification()? };
        config_builder.load_pem(keypair.cert(), keypair.key())?;
        let config = config_builder.build()?;
        let mut pair = TestPair::from_config(&config);
        pair.handshake()?;
        Ok(pair)
    }

    #[test]
    fn connection_fingerprint() -> Result<(), Box<dyn Error>> {
        let pair = simple_handshake()?;
        let client_hello = pair.server.client_hello()?;

        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
        let mut fingerprint = builder.build(&client_hello)?;

        let hash_size = fingerprint.hash_size()?;
        let mut hash = String::with_capacity(hash_size.try_into()?);
        let actual_hash_size = fingerprint.hash(&mut hash)?;
        assert_eq!(hash.len(), hash_size.try_into()?);
        assert_eq!(hash.len(), actual_hash_size.try_into()?);
        hex::decode(hash)?;

        let raw_size = fingerprint.raw_size()?;
        let mut raw = String::with_capacity(raw_size.try_into()?);
        let actual_raw_size = fingerprint.raw(&mut raw)?;
        assert_eq!(raw.len(), raw_size.try_into()?);
        assert_eq!(raw.len(), actual_raw_size.try_into()?);

        Ok(())
    }

    #[test]
    fn legacy_connection_fingerprint() -> Result<(), Box<dyn Error>> {
        let pair = simple_handshake()?;
        let client_hello = pair.server.client_hello()?;

        let mut hash = Vec::with_capacity(MD5_HASH_SIZE.try_into()?);
        let str_size = client_hello.fingerprint_hash(FingerprintType::JA3, &mut hash)?;
        assert_eq!(hash.len(), MD5_HASH_SIZE.try_into()?);

        let mut full_str = String::with_capacity(str_size.try_into()?);
        client_hello.fingerprint_string(FingerprintType::JA3, &mut full_str)?;
        assert_eq!(full_str.len(), str_size.try_into()?);

        Ok(())
    }

    #[test]
    fn known_value() -> Result<(), Box<dyn Error>> {
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;

        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
        let mut fingerprint = builder.build(&client_hello)?;

        let hash_size = fingerprint.hash_size()?;
        let mut hash = String::with_capacity(hash_size.try_into()?);
        let actual_hash_size = fingerprint.hash(&mut hash)?;
        assert_eq!(hash.len(), hash_size.try_into()?);
        assert_eq!(hash.len(), actual_hash_size.try_into()?);
        assert_eq!(hash, JA3_HASH);

        let raw_size = fingerprint.raw_size()?;
        let mut raw = String::with_capacity(raw_size.try_into()?);
        let actual_raw_size = fingerprint.raw(&mut raw)?;
        assert_eq!(raw.len(), raw_size.try_into()?);
        assert_eq!(raw.len(), actual_raw_size.try_into()?);
        assert_eq!(raw, JA3_FULL_STRING);

        Ok(())
    }

    #[test]
    fn legacy_known_value() -> Result<(), Box<dyn Error>> {
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;

        let mut hash = Vec::with_capacity(MD5_HASH_SIZE.try_into()?);
        let str_size = client_hello.fingerprint_hash(FingerprintType::JA3, &mut hash)?;
        assert_eq!(hash.len(), MD5_HASH_SIZE.try_into()?);
        assert_eq!(hash, hex::decode(JA3_HASH)?);

        let mut full_str = String::with_capacity(str_size.try_into()?);
        client_hello.fingerprint_string(FingerprintType::JA3, &mut full_str)?;
        assert_eq!(full_str.len(), str_size.try_into()?);
        assert_eq!(full_str, JA3_FULL_STRING);

        Ok(())
    }

    #[test]
    fn multiple_fingerprints() -> Result<(), Box<dyn Error>> {
        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;

        for _ in 1..10 {
            let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;
            let mut fingerprint = builder.build(&client_hello)?;

            let hash_size = fingerprint.hash_size()?;
            let mut hash = String::with_capacity(hash_size.try_into()?);
            fingerprint.hash(&mut hash)?;
            assert_eq!(hash, JA3_HASH);
        }

        Ok(())
    }

    #[test]
    fn multiple_fingerprints_reset() -> Result<(), Box<dyn Error>> {
        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;

        {
            let mut fingerprint = builder.build(&client_hello)?;
            let hash_size = fingerprint.hash_size()?;
            let mut hash = String::with_capacity(hash_size.try_into()?);

            // Before hash is called, there is no raw size
            fingerprint
                .raw_size()
                .expect_err("Raw size unexpectedly set");

            // After hash is called, there is a raw size
            fingerprint.hash(&mut hash)?;
            fingerprint.raw_size()?;
        }

        // Build another fingerprint with the same builder
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;
        let fingerprint = builder.build(&client_hello)?;

        // If the fingerprint state was properly reset, there is no raw size again
        fingerprint
            .raw_size()
            .expect_err("Fingerprint state not reset");

        Ok(())
    }

    #[test]
    fn output_resizing() -> Result<(), Box<dyn Error>> {
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;

        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
        let mut fingerprint = builder.build(&client_hello)?;

        // hash resizes output string
        let hash_size = fingerprint.hash_size()?;
        let hash_capacities = vec![hash_size, hash_size + 1, hash_size * 10];
        for initial_size in hash_capacities {
            let mut hash = String::with_capacity(initial_size.try_into()?);
            fingerprint.hash(&mut hash)?;
            assert_eq!(hash.len(), hash_size.try_into()?);
        }

        // raw resizes output string
        let raw_size = fingerprint.raw_size()?;
        let raw_capacities = vec![raw_size, raw_size + 1, raw_size * 10];
        for initial_size in raw_capacities {
            let mut raw = String::with_capacity(initial_size.try_into()?);
            fingerprint.raw(&mut raw)?;
            assert_eq!(raw.len(), raw_size.try_into()?);
        }

        Ok(())
    }

    #[test]
    fn legacy_hash_output_resizing() -> Result<(), Box<dyn Error>> {
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;
        let hash_capacities = vec![0, MD5_HASH_SIZE, 1_000];
        for initial_size in hash_capacities {
            let mut hash = Vec::with_capacity(initial_size.try_into()?);
            client_hello.fingerprint_hash(FingerprintType::JA3, &mut hash)?;
            assert_eq!(hash.len(), MD5_HASH_SIZE.try_into()?);
        }
        Ok(())
    }

    #[test]
    fn legacy_string_output_too_small() -> Result<(), Box<dyn Error>> {
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;
        let mut fingerprint_string = String::with_capacity(0);
        let fingerprint_err = client_hello
            .fingerprint_string(FingerprintType::JA3, &mut fingerprint_string)
            .unwrap_err();
        assert_eq!(fingerprint_err.kind(), ErrorType::UsageError);
        Ok(())
    }
}
