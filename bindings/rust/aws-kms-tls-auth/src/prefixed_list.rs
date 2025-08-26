// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::codec::{DecodeByteSource, DecodeValue, EncodeBytesSink, EncodeValue};
use std::{any::type_name, fmt::Debug, io::ErrorKind};

/// An opaque list of bytes, where the size of the list is prefixed on the wire as `L`.
///
/// This is just a convenience wrapper for `PrefixedList<u8, L>`.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct PrefixedBlob<L>(pub PrefixedList<u8, L>);

impl<L: TryFrom<usize>> PrefixedBlob<L> {
    pub fn new(inner_blob: Vec<u8>) -> anyhow::Result<Self> {
        let length_usize = inner_blob.len();
        let length = match length_usize.try_into() {
            Ok(length) => length,
            _ => anyhow::bail!(
                "failed to convert list length of {} into {}",
                length_usize,
                type_name::<L>()
            ),
        };

        let list = PrefixedList::<u8, L> {
            length,
            items: inner_blob,
        };
        Ok(Self(list))
    }
}

impl<L> PrefixedBlob<L> {
    pub fn blob(&self) -> &[u8] {
        &self.0.items
    }

    pub fn take_blob(self) -> Vec<u8> {
        self.0.items
    }
}

impl<L> Debug for PrefixedBlob<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PrefixedBlob")
            .field(&self.blob().len())
            .finish()
    }
}

impl<L> DecodeValue for PrefixedBlob<L>
where
    L: Copy + TryInto<usize> + DecodeValue,
{
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (inner, remaining) = buffer.decode_value()?;
        Ok((Self(inner), remaining))
    }
}

impl<L> EncodeValue for PrefixedBlob<L>
where
    L: EncodeValue,
{
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.encode_value(&self.0)?;
        Ok(())
    }
}

/// A list of `T`, where the byte length of the list is prefixed on the wire as `L`.
///
/// NOTE: length != count. A list of 100 u16's, has count 100 and size 200.
///
/// This unfortunately conflicts with the `.len()` function on rust `std` collections,
/// which will return the count of elements, and not their serialized length.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PrefixedList<T, L> {
    // We could remove the length since it's implicit in the items and their
    // encode implementation, but it makes the writing much uglier because you need
    // to use a "skip write" pattern.
    /// The length of the list in bytes
    length: L,
    items: Vec<T>,
}

impl<T, L> PrefixedList<T, L>
where
    L: Copy + Into<usize>,
{
    pub fn list(&self) -> &[T] {
        &self.items
    }
}

impl<T, L> DecodeValue for PrefixedList<T, L>
where
    L: Copy + TryInto<usize> + DecodeValue,
    T: DecodeValue,
{
    fn decode_from(buffer: &[u8]) -> std::io::Result<(Self, &[u8])> {
        let (length, mut buffer): (L, &[u8]) = buffer.decode_value()?;
        let length_usize: usize = match length.try_into() {
            Ok(length) => length,
            // this error should never happen except on 16 bit platforms. And we
            // don't ever expect to run on 16 bit platforms.
            Err(_) => {
                return Err(std::io::Error::new(
                    ErrorKind::FileTooLarge,
                    "failed to convert to usize",
                ))
            }
        };

        let current_buffer_size = buffer.len();
        if current_buffer_size < length_usize {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "not enough data available".to_owned(),
            ));
        }
        let target_buffer_size = current_buffer_size - length_usize;

        let mut list: Vec<T> = Vec::with_capacity(length_usize);
        while buffer.len() > target_buffer_size {
            let (item, remaining_buffer) = buffer.decode_value()?;
            list.push(item);
            buffer = remaining_buffer;
        }

        // this case might occur if the list was of length e.g. 21,
        // but each element was 2 bytes so we read 22,
        if buffer.len() != target_buffer_size {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "overread data, length field likely corrupt",
            ));
        }

        Ok((
            Self {
                length,
                items: list,
            },
            buffer,
        ))
    }
}

impl<T, L> EncodeValue for PrefixedList<T, L>
where
    T: EncodeValue,
    L: EncodeValue,
{
    fn encode_to(&self, buffer: &mut Vec<u8>) -> std::io::Result<()> {
        buffer.encode_value(&self.length)?;
        for item in &self.items {
            buffer.encode_value(item)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::prefixed_list::PrefixedBlob;

    #[test]
    fn list_too_long() {
        let error = PrefixedBlob::<u8>::new(vec![0; 257]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "failed to convert list length of 257 into u8"
        );
    }
}
