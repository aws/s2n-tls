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
    JA4,
}

impl From<FingerprintType> for s2n_tls_sys::s2n_fingerprint_type::Type {
    fn from(value: FingerprintType) -> Self {
        match value {
            FingerprintType::JA3 => s2n_tls_sys::s2n_fingerprint_type::FINGERPRINT_JA3,
            FingerprintType::JA4 => s2n_tls_sys::s2n_fingerprint_type::FINGERPRINT_JA4,
        }
    }
}

/// A fingerprint operation.
pub struct Fingerprint<'a>(&'a mut Builder);

impl Fingerprint<'_> {
    /// Size of the fingerprint hash.
    ///
    /// See s2n_fingerprint_get_hash_size in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/fingerprint.h).
    pub fn hash_size(&self) -> Result<usize, Error> {
        self.0.hash_size()
    }

    /// Calculate the fingerprint hash string.
    ///
    /// See s2n_fingerprint_get_hash in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/fingerprint.h).
    pub fn hash(&mut self) -> Result<&str, Error> {
        if self.0.hash.is_empty() {
            let mut output_size = 0;
            unsafe {
                s2n_fingerprint_get_hash(
                    self.0.ptr.as_ptr(),
                    self.0.hash.capacity() as u32,
                    self.0.hash.as_mut_ptr(),
                    &mut output_size,
                )
                .into_result()?;

                self.0.hash.as_mut_vec().set_len(output_size as usize);
            }
        }
        Ok(&self.0.hash)
    }

    /// Size of the raw fingerprint string.
    ///
    /// See s2n_fingerprint_get_raw_size in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/fingerprint.h).
    ///
    /// The size of the raw fingerprint string can't be known without calculating
    /// the fingerprint for a given ClientHello, so either [Fingerprint::hash()]
    /// or [Fingerprint::raw()] must be called before this method.
    pub fn raw_size(&self) -> Result<usize, Error> {
        let mut raw_size = 0;
        unsafe { s2n_fingerprint_get_raw_size(self.0.ptr.as_ptr(), &mut raw_size).into_result() }?;
        Ok(raw_size as usize)
    }

    /// Calculate the raw fingerprint string.
    ///
    /// See s2n_fingerprint_get_raw in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/fingerprint.h).
    ///
    /// The size of the raw fingerprint string can't be known without calculating
    /// the fingerprint for a given ClientHello. Before calling this method, you
    /// must either:
    ///
    /// 1. Call [`Builder::set_raw_size()`] to set a fixed maximum size.
    ///    If that maximum is insufficient, then this method will fail.
    ///
    /// ```no_run
    /// use s2n_tls::client_hello::ClientHello;
    /// use s2n_tls::fingerprint::{Fingerprint, FingerprintType};
    ///
    /// let client_hello_bytes = [ 0, 1, 2, 3, 4, 5 ];
    /// let client_hello = ClientHello::parse_client_hello(&client_hello_bytes)?;
    ///
    /// let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
    /// builder.set_raw_size(1000)?;
    /// let mut fingerprint = builder.build(&client_hello)?;
    /// let raw = fingerprint.raw()?;
    ///
    /// # Ok::<(), std::io::Error>(())
    /// ```
    ///
    /// 2. Call [`Fingerprint::hash()`] to calculate the exact fingerprint size.
    ///    This method will then ensure sufficient space is available to calculate
    ///    the raw string.
    ///
    /// ```no_run
    /// use s2n_tls::client_hello::ClientHello;
    /// use s2n_tls::fingerprint::{Fingerprint, FingerprintType};
    ///
    /// let client_hello_bytes = [ 0, 1, 2, 3, 4, 5 ];
    /// let client_hello = ClientHello::parse_client_hello(&client_hello_bytes)?;
    ///
    /// let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
    /// let mut fingerprint = builder.build(&client_hello)?;
    /// let hash = fingerprint.hash()?;
    /// let raw = fingerprint.raw()?;
    ///
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn raw(&mut self) -> Result<&str, Error> {
        if self.0.raw.is_empty() {
            if self.0.raw_size.is_none() {
                self.0.raw.reserve_exact(self.raw_size()?);
            };

            let mut output_size = 0;
            unsafe {
                s2n_fingerprint_get_raw(
                    self.0.ptr.as_ptr(),
                    self.0.raw.capacity() as u32,
                    self.0.raw.as_mut_ptr(),
                    &mut output_size,
                )
                .into_result()?;

                self.0.raw.as_mut_vec().set_len(output_size as usize);
            };
        }
        Ok(&self.0.raw)
    }

    pub fn builder(method: FingerprintType) -> Result<Builder, Error> {
        Builder::new(method)
    }
}

impl Drop for Fingerprint<'_> {
    /// Resets the underlying [Builder] for the next fingerprint.
    fn drop(&mut self) {
        unsafe {
            s2n_fingerprint_wipe(self.0.ptr.as_ptr())
                .into_result()
                .unwrap()
        };
        self.0.hash.clear();
        self.0.raw.clear();
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
///     let hash = fingerprint.hash()?;
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
pub struct Builder {
    ptr: NonNull<s2n_fingerprint>,
    hash: String,
    raw: String,
    raw_size: Option<usize>,
}

impl Builder {
    /// Creates a reusable [Builder].
    pub fn new(method: FingerprintType) -> Result<Self, Error> {
        crate::init::init();
        let ptr = unsafe { s2n_fingerprint_new(method.into()).into_result() }?;
        let hash = String::with_capacity(Self::ptr_hash_size(&ptr)?);
        let raw = String::new();
        Ok(Builder {
            ptr,
            hash,
            raw,
            raw_size: None,
        })
    }

    // Static version of hash_size, required to allocate enough memory in Builder::new()
    fn ptr_hash_size(ptr: &NonNull<s2n_fingerprint>) -> Result<usize, Error> {
        let mut hash_size = 0;
        unsafe { s2n_fingerprint_get_hash_size(ptr.as_ptr(), &mut hash_size).into_result() }?;
        Ok(hash_size as usize)
    }

    /// Size of the fingerprint hash.
    ///
    /// See s2n_fingerprint_get_hash_size in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/fingerprint.h).
    pub fn hash_size(&self) -> Result<usize, Error> {
        Self::ptr_hash_size(&self.ptr)
    }

    /// Set the maximum size of the raw fingerprint string.
    ///
    /// If the size is not set via this method, then [`Fingerprint::hash()`]
    /// must be called to calculate the size before [`Fingerprint::raw_size()`]
    /// or [`Fingerprint::raw()`] can be called.
    ///
    /// While the size of the fingerprint hash is fixed, the size of the raw string
    /// varies based on the size and contents of the ClientHello. Setting a fixed
    /// size prevents allocating an excessive amount of memory, but can lead to
    /// failures when calculating unexpectedly large fingerprints.
    pub fn set_raw_size(&mut self, size: usize) -> Result<&mut Self, Error> {
        self.raw_size = Some(size);
        self.raw.reserve_exact(size);
        Ok(self)
    }

    /// Creates a fingerprint operation for a given [ClientHello].
    pub fn build<'a>(&'a mut self, client_hello: &ClientHello) -> Result<Fingerprint<'a>, Error> {
        unsafe {
            s2n_fingerprint_set_client_hello(self.ptr.as_ptr(), client_hello.deref_mut_ptr())
                .into_result()
        }?;
        Ok(Fingerprint(self))
    }
}

impl Drop for Builder {
    /// Frees the memory associated with this [Builder].
    fn drop(&mut self) {
        let mut ptr: *mut s2n_fingerprint = unsafe { self.ptr.as_mut() };
        unsafe {
            let _ = s2n_fingerprint_free(std::ptr::addr_of_mut!(ptr));
        }
    }
}

// Legacy versions of the fingerprinting methods
const MD5_HASH_SIZE: u32 = 16;
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
    #[deprecated = "Users should prefer the Fingerprint::hash() method"]
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
    #[deprecated = "Users should prefer the Fingerprint::raw() method"]
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
        error::ErrorType,
        security,
        security::Policy,
        testing::{build_config, TestPair},
    };
    use std::{collections::HashSet, error::Error};

    const CLIENT_HELLO_BYTES: &[u8] = &[
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
        let config = build_config(&security::DEFAULT)?;
        let mut pair = TestPair::from_config(&config);
        pair.handshake()?;
        Ok(pair)
    }

    #[test]
    fn connection_fingerprint() -> Result<(), Box<dyn Error>> {
        let pair = simple_handshake()?;
        let client_hello = pair.server.client_hello()?;

        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
        let mut fingerprint = builder.build(client_hello)?;

        let hash_size = fingerprint.hash_size()?;
        let hash = fingerprint.hash()?;
        assert_eq!(hash.len(), hash_size);
        hex::decode(hash)?;

        let raw_size = fingerprint.raw_size()?;
        let raw = fingerprint.raw()?;
        assert_eq!(raw.len(), raw_size);

        Ok(())
    }

    #[test]
    fn known_value() -> Result<(), Box<dyn Error>> {
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;

        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
        let mut fingerprint = builder.build(&client_hello)?;

        let hash_size = fingerprint.hash_size()?;
        let hash = fingerprint.hash()?;
        assert_eq!(hash.len(), hash_size);
        assert_eq!(hash, JA3_HASH);

        let raw_size = fingerprint.raw_size()?;
        let raw = fingerprint.raw()?;
        assert_eq!(raw.len(), raw_size);
        assert_eq!(raw, JA3_FULL_STRING);

        Ok(())
    }

    #[test]
    fn multiple_fingerprints() -> Result<(), Box<dyn Error>> {
        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;

        for _ in 1..10 {
            let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;
            let mut fingerprint = builder.build(&client_hello)?;

            let hash = fingerprint.hash()?;
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

            // Before hash is called, there is no raw size
            fingerprint
                .raw_size()
                .expect_err("Raw size unexpectedly set");

            // After hash is called, there is a raw size
            fingerprint.hash()?;
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
    fn multiple_connection_fingerprints() -> Result<(), Box<dyn Error>> {
        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
        // Use a good variety of security policies
        let configs = [
            build_config(&Policy::from_version("20240501")?)?,
            build_config(&Policy::from_version("20240502")?)?,
            build_config(&Policy::from_version("20240503")?)?,
            build_config(&Policy::from_version("test_all")?)?,
        ];
        let mut fingerprints: Vec<String> = Vec::new();

        let handshake_count = configs.len() * 5;
        for i in 0..handshake_count {
            let i = i % configs.len();

            let config = &configs[i];
            let mut pair = TestPair::from_config(config);
            pair.handshake()?;

            let client_hello = pair.server.client_hello()?;
            let mut fingerprint = builder.build(client_hello)?;

            let hash = fingerprint.hash()?;
            hex::decode(hash)?;

            // Verify that the same config produces the same fingerprint
            if let Some(previous) = fingerprints.get(i) {
                assert_eq!(previous.as_str(), hash);
            } else {
                fingerprints.push(hash.to_string());
            }
        }
        assert_eq!(configs.len(), fingerprints.len());

        // Verify that we actually tested different unique fingerprints
        let unique: HashSet<&String> = HashSet::from_iter(fingerprints.iter());
        assert_eq!(unique.len(), fingerprints.len());

        Ok(())
    }

    #[test]
    fn raw_sufficient_memory() -> Result<(), Box<dyn Error>> {
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;

        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
        builder.set_raw_size(JA3_FULL_STRING.len())?;

        let mut fingerprint = builder.build(&client_hello)?;
        let raw = fingerprint.raw()?;
        assert_eq!(raw, JA3_FULL_STRING);

        Ok(())
    }

    #[test]
    fn raw_insufficient_memory() -> Result<(), Box<dyn Error>> {
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;

        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;
        builder.set_raw_size(JA3_FULL_STRING.len() - 1)?;

        let mut fingerprint = builder.build(&client_hello)?;
        let error = fingerprint
            .raw()
            .expect_err("Calculated raw string despite insufficient memory");
        assert_eq!(error.kind(), ErrorType::UsageError);
        assert_eq!(error.name(), "S2N_ERR_INSUFFICIENT_MEM_SIZE");

        Ok(())
    }

    #[test]
    fn hash_does_not_allocate_memory() -> Result<(), Box<dyn Error>> {
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;

        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;

        for _ in 0..10 {
            let snapshot = checkers::with(|| {
                let mut fingerprint = builder.build(&client_hello).unwrap();
                fingerprint.hash().unwrap();
            });
            assert!(snapshot.events.is_empty());
        }

        Ok(())
    }

    #[test]
    fn raw_may_allocate_memory() -> Result<(), Box<dyn Error>> {
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;

        let mut builder = Fingerprint::builder(FingerprintType::JA3)?;

        let minimum_size = JA3_FULL_STRING.len();
        let large_size = minimum_size + 100;

        // If we want to allocate the known value of the raw string,
        // then that allocation must happen when raw() is called rather than
        // when the fingerprint is built.
        let snapshot = checkers::with(|| {
            let mut fingerprint = builder.build(&client_hello).unwrap();
            // Calculating the hash is necessary to calculate the raw_size,
            // But the hash_does_not_allocate_memory test proves this does not
            // allocate any memory.
            fingerprint.hash().unwrap();

            fingerprint.raw().unwrap();
        });
        // Expect a single allocation to allocate the raw string
        assert_eq!(snapshot.events.allocs(), 1);
        assert_eq!(snapshot.events.reallocs(), 0);
        assert_eq!(snapshot.events.frees(), 0);
        assert_eq!(snapshot.events.max_memory_used().unwrap(), minimum_size);

        // Snapshots must be cumulative to accurately track total allocations,
        // so keep track of the current snapshot.
        let mut full_snapshot = snapshot;

        // Expect that repeating either the build or the calculation does not
        // lead to any new allocations.
        let snapshot = checkers::with(|| {
            for _ in 0..10 {
                let mut fingerprint = builder.build(&client_hello).unwrap();
                // Calculating the hash is necessary to calculate the raw_size,
                // But the hash_does_not_allocate_memory test proves this does not
                // allocate any memory.
                fingerprint.hash().unwrap();

                for _ in 0..10 {
                    fingerprint.raw().unwrap();
                }
            }
        });
        assert!(snapshot.events.is_empty());

        // If we set a larger raw size on the builder,
        // then the raw string is reallocated.
        let snapshot = checkers::with(|| {
            builder.set_raw_size(large_size).unwrap();
        });
        assert_eq!(snapshot.events.allocs(), 0);
        assert_eq!(snapshot.events.reallocs(), 1);
        assert_eq!(snapshot.events.frees(), 0);

        // Snapshots must be cumulative to accurately track total allocations,
        // so add the new snapshot events.
        for event in snapshot.events.as_slice() {
            full_snapshot.events.push(event.clone());
        }
        // The new total memory should be the larger size we set on the builder.
        assert_eq!(full_snapshot.events.max_memory_used().unwrap(), large_size);

        // If the raw size was set on the builder, then the raw string is not
        // allocated when raw() is called.
        let snapshot = checkers::with(|| {
            let mut fingerprint = builder.build(&client_hello).unwrap();
            fingerprint.raw().unwrap();
        });
        assert!(snapshot.events.is_empty());

        // If we set a smaller raw size on the builder,
        // then the raw string is not reallocated.
        let snapshot = checkers::with(|| {
            builder.set_raw_size(minimum_size).unwrap();
        });
        assert!(snapshot.events.is_empty());

        // Recalculating the raw string does not reallocate the raw string
        let snapshot = checkers::with(|| {
            for _ in 0..10 {
                let mut fingerprint = builder.build(&client_hello).unwrap();
                fingerprint.raw().unwrap();
            }
        });
        assert!(snapshot.events.is_empty());

        Ok(())
    }

    #[test]
    #[allow(deprecated)]
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
    #[allow(deprecated)]
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
    #[allow(deprecated)]
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
    #[allow(deprecated)]
    fn legacy_string_output_too_small() -> Result<(), Box<dyn Error>> {
        let client_hello = ClientHello::parse_client_hello(CLIENT_HELLO_BYTES)?;
        let mut fingerprint_string = String::with_capacity(JA3_FULL_STRING.len() - 1);
        let fingerprint_err = client_hello
            .fingerprint_string(FingerprintType::JA3, &mut fingerprint_string)
            .unwrap_err();
        assert_eq!(fingerprint_err.kind(), ErrorType::UsageError);
        assert_eq!(fingerprint_err.name(), "S2N_ERR_INSUFFICIENT_MEM_SIZE");
        Ok(())
    }
}
