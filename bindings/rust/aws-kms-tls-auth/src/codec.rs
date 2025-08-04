// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The `codec` module contains traits that are used for serializing and deserializing
//! various structs.
//!
//! ### Compare To
//! [`s2n_codec`](https://crates.io/crates/s2n-codec) provides much richer functionality,
//! but that richer functionality comes at the cost of generic lifetimes, non-std
//! structs, and more generics. For example, s2n-codec requires a specialized
//! `DecoderBuffer<'a>`, but this codec module just uses a plain byte slice `&[u8]`.
//!
//! [`binary_serde`](https://crates.io/crates/binary_serde) doesn't support dynamically
//! sized types like `Vec<T>`, which makes it a no-go for TLS use cases, because
//! TLS is _filled_ with lists of items.
//!
//! ### Future Development
//! Ideally all of the codec stuff would be moved to a different crate, and we'd
//! have proc macros to derive the `EncodeValue` and `DecodeValue` traits.

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{self, ErrorKind, Read, Write};

/// This trait defines a source that values can be decoded from.
pub trait DecodeByteSource<T: DecodeValue>: Sized {
    fn decode_value(&self) -> io::Result<(T, Self)>;
}

/// This trait defines a sink that values can be encoded to. Currently this is
/// only implemented for `Vec<u8>`.
///
/// This is less efficient than relying on buffers, because encode calls might
/// result in allocations. But the benefit is that it's much more ergonomic.
pub trait EncodeBytesSink<T: EncodeValue>: Sized {
    fn encode_value(&mut self, value: &T) -> io::Result<()>;
}

/// This trait defines a type that can be decoded from bytes.
pub trait DecodeValue: Sized {
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])>;

    /// decode a value from `buffer`, using all of the bytes.
    ///
    /// If buffer was not entirely consumed, an error is returned.
    fn decode_from_exact(buffer: &[u8]) -> std::io::Result<Self> {
        let (value, buffer) = Self::decode_from(buffer)?;
        if !buffer.is_empty() {
            Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "unexpected data left over",
            ))
        } else {
            Ok(value)
        }
    }
}

/// This trait defines a type that can be encoded into bytes.
pub trait EncodeValue: Sized {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()>;

    fn encode_to_vec(&self) -> std::io::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.encode_to(&mut buffer)?;
        Ok(buffer)
    }
}

//////////////////////////// Source + Sink Impls ///////////////////////////////

impl<T: DecodeValue> DecodeByteSource<T> for &[u8] {
    fn decode_value(&self) -> io::Result<(T, Self)> {
        T::decode_from(self)
    }
}

impl<T: EncodeValue> EncodeBytesSink<T> for Vec<u8> {
    fn encode_value(&mut self, value: &T) -> io::Result<()> {
        value.encode_to(self)
    }
}

//////////////////////////// Primitive Impls ///////////////////////////////////

impl DecodeValue for u8 {
    fn decode_from(mut buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let value = buffer.read_u8()?;
        Ok((value, buffer))
    }
}

impl DecodeValue for u16 {
    fn decode_from(mut buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let value = buffer.read_u16::<BigEndian>()?;
        Ok((value, buffer))
    }
}

impl DecodeValue for u32 {
    fn decode_from(mut buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let value = buffer.read_u32::<BigEndian>()?;
        Ok((value, buffer))
    }
}

impl DecodeValue for u64 {
    fn decode_from(mut buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let value = buffer.read_u64::<BigEndian>()?;
        Ok((value, buffer))
    }
}

impl EncodeValue for u8 {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.write_all(&[*self])?;
        Ok(())
    }
}

impl EncodeValue for u16 {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

impl EncodeValue for u32 {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

impl EncodeValue for u64 {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.write_all(&self.to_be_bytes())?;
        Ok(())
    }
}

// Implement Decode and Encode for byte arrays

impl<const L: usize> DecodeValue for [u8; L] {
    fn decode_from(mut buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let mut value = [0; L];
        buffer.read_exact(&mut value)?;
        Ok((value, buffer))
    }
}

impl<const L: usize> EncodeValue for [u8; L] {
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.write_all(self)?;
        Ok(())
    }
}
