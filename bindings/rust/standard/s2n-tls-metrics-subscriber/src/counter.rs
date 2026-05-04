// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic per-kind counter abstraction used by the handshake record.
//!
//! A [`Counter<N, T>`] is a dense array of `N` [`AtomicU64`] slots indexed by
//! the slot positions that [`FiniteCounter<N>`] assigns to each value of `T`.
//! Hot path is a single relaxed `fetch_add` on the slot for an element.
//!
//! [`FiniteCounter<N>`]: crate::static_lists::FiniteCounter

use std::{
    marker::PhantomData,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::static_lists::FiniteCounter;

/// Atomic-backed counter storage for one parameter kind.
///
/// An inline array of `N` `AtomicU64`s. Hot path is one relaxed `fetch_add`
/// on the slot for `element`.
pub(crate) struct Counter<const N: usize, T: FiniteCounter<N>> {
    slots: [AtomicU64; N],
    element: PhantomData<T>,
}

impl<const N: usize, T: FiniteCounter<N>> Counter<N, T> {
    pub(crate) fn new() -> Self {
        // AtomicU64 isn't Copy, so initialize element-wise.
        let slots: [AtomicU64; N] = [0u64; N].map(AtomicU64::new);
        Self {
            slots,
            element: PhantomData,
        }
    }

    /// Increment the slot for `element`. No-op if `element` is not in
    /// [`FiniteCounter::ELEMENTS`] — wire types decoded from client-hello
    /// bytes may not match any known value.
    pub(crate) fn increment(&self, element: &T) {
        if let Some(slot) = element.slot_from_key()
            && let Some(counter) = self.slots.get(slot)
        {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Snapshot current values. `&mut self` guarantees no concurrent writer,
    /// so relaxed loads are sufficient.
    pub(crate) fn freeze(&mut self) -> FrozenCounter<N, T> {
        let snapshot: Box<[u64]> = self
            .slots
            .iter()
            .map(|a| a.load(Ordering::Relaxed))
            .collect();
        FrozenCounter {
            slots: snapshot,
            element: PhantomData,
        }
    }
}

impl<const N: usize, T: FiniteCounter<N>> std::fmt::Debug for Counter<N, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = format!("Counter<{}>", std::any::type_name::<T>());
        let mut dbg = f.debug_struct(&name);
        for (slot, atomic) in self.slots.iter().enumerate() {
            let value = atomic.load(Ordering::Relaxed);
            if value > 0 {
                dbg.field(&slot.to_string(), &value);
            }
        }
        dbg.finish()
    }
}

/// Exportable, immutable snapshot of a [`Counter<N, T>`].
pub(crate) struct FrozenCounter<const N: usize, T: FiniteCounter<N>> {
    pub(super) slots: Box<[u64]>,
    pub(super) element: PhantomData<T>,
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
    /// `(description, count)` pairs for non-zero slots, in slot order.
    /// Every element in [`Self::ELEMENTS`] has a description, enforced by
    /// the `every_slot_has_description` test for each concrete impl; the
    /// `filter_map` is defensive.
    pub(crate) fn iter_non_zero(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c > 0)
            .filter_map(|(slot, &c)| {
                T::key_from_slot(slot)
                    .and_then(|key| key.description())
                    .map(|name| (name, c))
            })
    }

    #[cfg(test)]
    pub(crate) fn total(&self) -> u64 {
        self.slots.iter().sum()
    }

    #[cfg(test)]
    pub(crate) fn slots_for_test(&self) -> &[u64] {
        &self.slots
    }

    /// Count for `description`, or `0` if unknown to this reader's kind.
    #[cfg(test)]
    pub(crate) fn count_for(&self, description: &str) -> u64 {
        T::from_description(description)
            .and_then(|element| element.slot_from_key())
            .and_then(|slot| self.slots.get(slot).copied())
            .unwrap_or(0)
    }
}

impl<const N: usize, T: FiniteCounter<N>> Clone for FrozenCounter<N, T> {
    fn clone(&self) -> Self {
        Self {
            slots: self.slots.clone(),
            element: PhantomData,
        }
    }
}

impl<const N: usize, T: FiniteCounter<N>> PartialEq for FrozenCounter<N, T> {
    fn eq(&self, other: &Self) -> bool {
        self.slots == other.slots
    }
}

impl<const N: usize, T: FiniteCounter<N>> Default for FrozenCounter<N, T> {
    fn default() -> Self {
        Self {
            slots: vec![0u64; N].into_boxed_slice(),
            element: PhantomData,
        }
    }
}

impl<const N: usize, T: FiniteCounter<N>> serde::Serialize for FrozenCounter<N, T> {
    /// Emit non-zero slots as a map keyed by IANA wire id. Pre-counting
    /// gives length-prefixed formats (CBOR, postcard) the exact pair count.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let non_zero_count = self.slots.iter().filter(|&&c| c > 0).count();
        let mut map = serializer.serialize_map(Some(non_zero_count))?;
        for (slot, &value) in self.slots.iter().enumerate() {
            if value > 0 {
                let key = T::key_from_slot(slot)
                    .expect("slot < N, so key_from_slot is Some")
                    .iana_id();
                map.serialize_entry(&key, &value)?;
            }
        }
        map.end()
    }
}

impl<'de, const N: usize, T: FiniteCounter<N>> serde::Deserialize<'de> for FrozenCounter<N, T> {
    /// Decode a map of `(iana_id: u16, u64)` pairs. Missing slots default
    /// to 0; unknown keys are dropped and logged at `debug!`. Duplicate
    /// keys follow serde's last-wins policy.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor<const N: usize, T: FiniteCounter<N>>(PhantomData<T>);

        impl<'de, const N: usize, T: FiniteCounter<N>> serde::de::Visitor<'de> for MapVisitor<N, T> {
            type Value = FrozenCounter<N, T>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a map of (IANA wire id, u64) pairs")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut slots: Box<[u64]> = vec![0u64; N].into_boxed_slice();
                let mut unknown: Vec<u16> = Vec::new();
                while let Some((key, value)) = access.next_entry::<u16, u64>()? {
                    match T::from_iana_id(key).and_then(|e| e.slot_from_key()) {
                        Some(slot) => slots[slot] = value,
                        None => unknown.push(key),
                    }
                }
                if !unknown.is_empty() {
                    // Dropping unknown keys is the designed cross-version
                    // behavior. Debug level keeps it discoverable without
                    // generating sustained volume during normal operation.
                    tracing::debug!(
                        kind = std::any::type_name::<T>(),
                        unknown_count = unknown.len(),
                        unknown = ?unknown,
                        "FrozenCounter deserialize dropped unknown IANA ids",
                    );
                }
                Ok(FrozenCounter {
                    slots,
                    element: PhantomData,
                })
            }
        }

        deserializer.deserialize_map(MapVisitor::<N, T>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_lists::{
        CIPHER_COUNT, Cipher, GROUP_COUNT, Group, PROTOCOL_COUNT, SIGNATURE_COUNT, Signature,
        Version,
    };

    /// Assert `from_iana_id(element.iana_id()) == Some(element)` and
    /// `slot_from_key` is a bijection for every slot of `T`.
    fn roundtrip<const N: usize, T: FiniteCounter<N>>() {
        for slot in 0..N {
            let element = T::key_from_slot(slot).expect("slot < N");
            assert_eq!(
                element.slot_from_key(),
                Some(slot),
                "slot_from_key round-trip failed at slot {slot}",
            );
            let wire = element.iana_id();
            let recovered = T::from_iana_id(wire).expect("iana id must round-trip");
            assert_eq!(
                recovered.slot_from_key(),
                Some(slot),
                "iana id round-trip landed on wrong slot at {slot}",
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

    /// `iter_non_zero` drops slots whose element has no `description()`.
    /// Assert every element in `ELEMENTS` has one so a missing description
    /// becomes a test failure rather than silently lost metrics.
    fn every_slot_has_description<const N: usize, T: FiniteCounter<N>>() {
        for slot in 0..N {
            let element = T::key_from_slot(slot).expect("slot < N");
            assert!(
                element.description().is_some(),
                "slot {slot} of {} has no description",
                std::any::type_name::<T>(),
            );
        }
    }

    #[test]
    fn version_every_slot_has_description() {
        every_slot_has_description::<PROTOCOL_COUNT, Version>();
    }

    #[test]
    fn cipher_every_slot_has_description() {
        every_slot_has_description::<CIPHER_COUNT, Cipher>();
    }

    #[test]
    fn group_every_slot_has_description() {
        every_slot_has_description::<GROUP_COUNT, Group>();
    }

    #[test]
    fn signature_every_slot_has_description() {
        every_slot_has_description::<SIGNATURE_COUNT, Signature>();
    }

    #[test]
    fn counter_freeze_snapshots_slots() {
        let mut counter = Counter::<CIPHER_COUNT, Cipher>::new();
        let slot_2_cipher = Cipher::key_from_slot(2).unwrap();
        let slot_7_cipher = Cipher::key_from_slot(7).unwrap();
        for _ in 0..3 {
            counter.increment(&slot_2_cipher);
        }
        for _ in 0..2 {
            counter.increment(&slot_7_cipher);
        }

        let frozen = counter.freeze();

        assert_eq!(frozen.slots.len(), CIPHER_COUNT);
        assert_eq!(frozen.slots[2], 3);
        assert_eq!(frozen.slots[7], 2);
        for (i, &value) in frozen.slots.iter().enumerate() {
            if i == 2 || i == 7 {
                continue;
            }
            assert_eq!(value, 0, "slot {i} expected 0, got {value}");
        }
    }

    #[test]
    fn frozen_counter_iter_non_zero_skips_zeros() {
        let mut counter = Counter::<CIPHER_COUNT, Cipher>::new();
        let slot_2_cipher = Cipher::key_from_slot(2).unwrap();
        let slot_7_cipher = Cipher::key_from_slot(7).unwrap();
        for _ in 0..3 {
            counter.increment(&slot_2_cipher);
        }
        for _ in 0..5 {
            counter.increment(&slot_7_cipher);
        }
        let frozen = counter.freeze();

        let pairs: Vec<(&'static str, u64)> = frozen.iter_non_zero().collect();

        let expected_slot_2 = slot_2_cipher.description().unwrap();
        let expected_slot_7 = slot_7_cipher.description().unwrap();

        assert_eq!(pairs, vec![(expected_slot_2, 3), (expected_slot_7, 5)]);
    }

    #[test]
    fn frozen_counter_serialize_json_emits_iana_keys() {
        // Slot 0 of Cipher is TLS_AES_128_GCM_SHA256, IANA id 0x1301
        // (= 4865 decimal).
        let mut counter = Counter::<CIPHER_COUNT, Cipher>::new();
        let slot_0_cipher = Cipher::key_from_slot(0).unwrap();
        for _ in 0..3 {
            counter.increment(&slot_0_cipher);
        }
        let frozen = counter.freeze();

        let value = serde_json::to_value(&frozen).unwrap();
        let map = value.as_object().unwrap();

        assert_eq!(map.len(), 1);
        assert_eq!(map.get("4865").and_then(|v| v.as_u64()), Some(3));
    }

    #[test]
    fn frozen_counter_deserialize_unknown_key_dropped() {
        // 4865 is TLS_AES_128_GCM_SHA256 (slot 0); 65535 is not in the
        // cipher registry, so it must be dropped on decode.
        assert!(Cipher::from_iana_id(65535).is_none());

        let json = r#"{"4865": 3, "65535": 7}"#;
        let decoded: FrozenCounter<CIPHER_COUNT, Cipher> = serde_json::from_str(json).unwrap();

        let mut expected_counter = Counter::<CIPHER_COUNT, Cipher>::new();
        let slot_0_cipher = Cipher::key_from_slot(0).unwrap();
        for _ in 0..3 {
            expected_counter.increment(&slot_0_cipher);
        }
        let expected = expected_counter.freeze();

        assert_eq!(decoded, expected);
    }

    #[test]
    fn frozen_counter_deserialize_missing_slots_are_zero() {
        let decoded: FrozenCounter<CIPHER_COUNT, Cipher> = serde_json::from_str("{}").unwrap();

        assert_eq!(decoded, FrozenCounter::<CIPHER_COUNT, Cipher>::default());
    }
}

#[cfg(test)]
mod malformed {
    //! `Deserialize` on `FrozenCounter<N, T>` must return a descriptive serde
    //! error (not panic) when its input is syntactically invalid.

    use super::*;
    use crate::static_lists::{CIPHER_COUNT, Cipher};

    #[test]
    fn json_non_integer_key_returns_error() {
        let json = r#"{"foo": 42}"#;
        serde_json::from_str::<FrozenCounter<CIPHER_COUNT, Cipher>>(json).unwrap_err();
    }

    #[test]
    fn json_non_integer_value_returns_error() {
        let json = r#"{"4865": "not a number"}"#;
        serde_json::from_str::<FrozenCounter<CIPHER_COUNT, Cipher>>(json).unwrap_err();
    }
}
