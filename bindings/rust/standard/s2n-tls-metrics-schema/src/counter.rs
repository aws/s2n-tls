// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic per-kind counter abstraction used by the handshake record.
//!
//! A [`FrozenCounter<N, T>`] is a dense array of `N` `u64` slots indexed by
//! the slot positions that [`FiniteCounter<N>`] assigns to each value of `T`.

use std::marker::PhantomData;

use crate::static_lists::FiniteCounter;

/// Exportable, immutable snapshot of a counter.
#[derive(Clone, PartialEq)]
pub struct FrozenCounter<const N: usize, T: FiniteCounter<N>> {
    pub slots: [u64; N],
    pub element: PhantomData<T>,
}

impl<const N: usize, T: FiniteCounter<N>> std::fmt::Debug for FrozenCounter<N, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct SlotList<'a>(&'a [u64]);
        impl<'a> std::fmt::Debug for SlotList<'a> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_list().entries(self.0.iter()).finish()
            }
        }

        let name = format!("FrozenCounter<{}>", std::any::type_name::<T>());
        f.debug_struct(&name)
            .field("slots", &SlotList(&self.slots))
            .finish()
    }
}

impl<const N: usize, T: FiniteCounter<N>> FrozenCounter<N, T> {
    /// Creates a `FrozenCounter` from raw slot values.
    pub fn from_slots(slots: [u64; N]) -> Self {
        Self {
            slots,
            element: PhantomData,
        }
    }

    /// The underlying slot array in element order.
    pub fn slots(&self) -> &[u64; N] {
        &self.slots
    }

    /// Sum of all slot values.
    pub fn total(&self) -> u64 {
        self.slots.iter().sum()
    }

    /// `(slot, element, count)` triples for non-zero slots, in slot order.
    pub fn iter_non_zero(&self) -> impl Iterator<Item = (usize, T, u64)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c > 0)
            .filter_map(|(slot, &c)| T::key_from_slot(slot).map(|key| (slot, key, c)))
    }
}

impl<const N: usize, T: FiniteCounter<N>> Default for FrozenCounter<N, T> {
    fn default() -> Self {
        Self {
            slots: [0u64; N],
            element: PhantomData,
        }
    }
}

impl<const N: usize, T> serde::Serialize for FrozenCounter<N, T>
where
    T: FiniteCounter<N> + serde::Serialize,
{
    /// Emit non-zero slots as a sequence of `(T, u64)` pairs. Each `T`
    /// serializes itself in value position, so element types whose native
    /// form isn't a primitive (e.g. `Cipher`'s `[u8; 2]`) round-trip via
    /// plain `#[derive]`. Pre-counting gives length-prefixed formats
    /// (CBOR, postcard) the exact pair count.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let non_zero_count = self.slots.iter().filter(|&&c| c > 0).count();
        let mut seq = serializer.serialize_seq(Some(non_zero_count))?;
        for (_slot, element, count) in self.iter_non_zero() {
            seq.serialize_element(&(element, count))?;
        }
        seq.end()
    }
}

impl<'de, const N: usize, T> serde::Deserialize<'de> for FrozenCounter<N, T>
where
    T: FiniteCounter<N> + serde::de::DeserializeOwned + std::fmt::Display,
{
    /// Decode a sequence of `(T, u64)` pairs. Each `T` parses itself; the
    /// counter then filters by [`FiniteCounter::slot_from_key`], so values
    /// whose wire form is well-formed but unknown to this build's `ELEMENTS`
    /// are dropped (and logged at `debug!`). Missing slots default to 0.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SeqVisitor<const N: usize, T: FiniteCounter<N>>(PhantomData<T>);

        impl<'de, const N: usize, T> serde::de::Visitor<'de> for SeqVisitor<N, T>
        where
            T: FiniteCounter<N> + serde::de::DeserializeOwned + std::fmt::Display,
        {
            type Value = FrozenCounter<N, T>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    f,
                    "a sequence of ({}, u64) pairs",
                    std::any::type_name::<T>()
                )
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut slots: [u64; N] = [0u64; N];
                let mut unknown: Vec<T> = Vec::new();
                while let Some((element, value)) = access.next_element::<(T, u64)>()? {
                    match element.slot_from_key() {
                        Some(slot) => slots[slot] = value,
                        None => unknown.push(element),
                    }
                }
                if !unknown.is_empty() {
                    let unknown_display: Vec<String> =
                        unknown.iter().map(|e| e.to_string()).collect();
                    tracing::debug!(
                        kind = std::any::type_name::<T>(),
                        unknown_count = unknown.len(),
                        unknown = ?unknown_display,
                        "FrozenCounter deserialize dropped unknown elements",
                    );
                }
                Ok(FrozenCounter {
                    slots,
                    element: PhantomData,
                })
            }
        }

        deserializer.deserialize_seq(SeqVisitor::<N, T>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_lists::{
        CIPHER_COUNT, Cipher, GROUP_COUNT, Group, PROTOCOL_COUNT, SIGNATURE_COUNT, Signature,
        Version,
    };

    fn roundtrip<const N: usize, T>()
    where
        T: FiniteCounter<N> + serde::Serialize + serde::de::DeserializeOwned,
    {
        for slot in 0..N {
            let element = T::key_from_slot(slot).expect("slot < N");
            assert_eq!(
                element.slot_from_key(),
                Some(slot),
                "slot_from_key round-trip failed at slot {slot}",
            );
            let json = serde_json::to_string(&element).expect("serialize");
            let recovered: T = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(
                recovered.slot_from_key(),
                Some(slot),
                "serde round-trip landed on wrong slot at {slot}",
            );
        }
    }

    #[test]
    fn version_roundtrip() {
        roundtrip::<PROTOCOL_COUNT, Version>();
    }

    #[test]
    fn cipher_roundtrip() {
        roundtrip::<CIPHER_COUNT, Cipher>();
    }

    #[test]
    fn group_roundtrip() {
        roundtrip::<GROUP_COUNT, Group>();
    }

    #[test]
    fn signature_roundtrip() {
        roundtrip::<SIGNATURE_COUNT, Signature>();
    }

    #[test]
    fn frozen_counter_serialize_json_emits_iana_pairs() {
        let mut slots = [0u64; CIPHER_COUNT];
        slots[0] = 3;
        let frozen = FrozenCounter::<CIPHER_COUNT, Cipher>::from_slots(slots);

        let value = serde_json::to_value(&frozen).unwrap();
        assert_eq!(value, serde_json::json!([[[0x13, 0x01], 3]]));
    }

    #[test]
    fn frozen_counter_deserialize_unknown_element_dropped() {
        let json = r#"[[[19, 1], 3], [[255, 255], 7]]"#;
        let decoded: FrozenCounter<CIPHER_COUNT, Cipher> = serde_json::from_str(json).unwrap();

        let mut expected_slots = [0u64; CIPHER_COUNT];
        expected_slots[0] = 3;
        let expected = FrozenCounter::<CIPHER_COUNT, Cipher>::from_slots(expected_slots);

        assert_eq!(decoded, expected);
    }

    #[test]
    fn frozen_counter_deserialize_missing_slots_are_zero() {
        let decoded: FrozenCounter<CIPHER_COUNT, Cipher> = serde_json::from_str("[]").unwrap();
        assert_eq!(decoded, FrozenCounter::<CIPHER_COUNT, Cipher>::default());
    }

    #[test]
    fn frozen_counter_iter_non_zero_skips_zeros() {
        let mut slots = [0u64; CIPHER_COUNT];
        slots[2] = 3;
        slots[7] = 5;
        let frozen = FrozenCounter::<CIPHER_COUNT, Cipher>::from_slots(slots);

        let pairs: Vec<(usize, Cipher, u64)> = frozen.iter_non_zero().collect();

        let slot_2_cipher = Cipher::key_from_slot(2).unwrap();
        let slot_7_cipher = Cipher::key_from_slot(7).unwrap();
        assert_eq!(pairs, vec![(2, slot_2_cipher, 3), (7, slot_7_cipher, 5)]);
    }
}

#[cfg(test)]
mod malformed {
    use super::*;
    use crate::static_lists::{CIPHER_COUNT, Cipher};

    #[test]
    fn json_malformed_element_returns_error() {
        let json = r#"[["not a cipher", 42]]"#;
        serde_json::from_str::<FrozenCounter<CIPHER_COUNT, Cipher>>(json).unwrap_err();
    }

    #[test]
    fn json_non_integer_value_returns_error() {
        let json = r#"[[[19, 1], "not a number"]]"#;
        serde_json::from_str::<FrozenCounter<CIPHER_COUNT, Cipher>>(json).unwrap_err();
    }

    #[test]
    fn json_map_shape_returns_error() {
        let json = r#"{"4865": 3}"#;
        serde_json::from_str::<FrozenCounter<CIPHER_COUNT, Cipher>>(json).unwrap_err();
    }
}
