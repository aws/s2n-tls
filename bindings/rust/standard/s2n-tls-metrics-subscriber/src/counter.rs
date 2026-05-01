// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic per-kind counter abstraction used by the handshake record.
//!
//! `ParameterKind` ties a TLS parameter kind (version, cipher, group,
//! signature) to its slot count, wire key, and description.

use std::{marker::PhantomData, sync::atomic::AtomicU64};

use crate::static_lists::{
    CIPHER_COUNT, GROUP_COUNT, PROTOCOL_COUNT, SIGNATURE_COUNT, TlsParam, cipher_iana_id,
    cipher_slot_for_iana_id, group_iana_id, group_slot_for_iana_id, signature_iana_id,
    signature_slot_for_iana_id, version_iana_id, version_slot_for_iana_id,
};

/// A TLS parameter kind with a fixed, known-at-build-time set of values.
pub(crate) trait ParameterKind: 'static {
    /// Number of slots for this kind.
    const LEN: usize;

    /// IANA numeric id on the wire.
    type WireKey: Copy
        + Eq
        + Ord
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + core::fmt::Debug;

    /// Slot → wire key. Must be total for `slot < LEN`.
    fn slot_to_wire_key(slot: usize) -> Self::WireKey;

    /// Wire key → slot, or `None` if unknown.
    fn wire_key_to_slot(key: Self::WireKey) -> Option<usize>;

    /// Human-readable label for `metrique_writer::Entry`.
    fn slot_to_description(slot: usize) -> Option<&'static str>;

    /// The `TlsParam` discriminant this kind corresponds to.
    #[cfg(test)]
    const TLS_PARAM: TlsParam;
}

pub(crate) struct VersionKind;

impl ParameterKind for VersionKind {
    const LEN: usize = PROTOCOL_COUNT;
    type WireKey = u16;

    fn slot_to_wire_key(slot: usize) -> Self::WireKey {
        version_iana_id(slot).expect("slot < LEN")
    }

    fn wire_key_to_slot(key: Self::WireKey) -> Option<usize> {
        version_slot_for_iana_id(key)
    }

    fn slot_to_description(slot: usize) -> Option<&'static str> {
        TlsParam::Version.index_to_description(slot)
    }

    #[cfg(test)]
    const TLS_PARAM: TlsParam = TlsParam::Version;
}

pub(crate) struct CipherKind;

impl ParameterKind for CipherKind {
    const LEN: usize = CIPHER_COUNT;
    type WireKey = u16;

    fn slot_to_wire_key(slot: usize) -> Self::WireKey {
        cipher_iana_id(slot).expect("slot < LEN")
    }

    fn wire_key_to_slot(key: Self::WireKey) -> Option<usize> {
        cipher_slot_for_iana_id(key)
    }

    fn slot_to_description(slot: usize) -> Option<&'static str> {
        TlsParam::Cipher.index_to_description(slot)
    }

    #[cfg(test)]
    const TLS_PARAM: TlsParam = TlsParam::Cipher;
}

pub(crate) struct GroupKind;

impl ParameterKind for GroupKind {
    const LEN: usize = GROUP_COUNT;
    type WireKey = u16;

    fn slot_to_wire_key(slot: usize) -> Self::WireKey {
        group_iana_id(slot).expect("slot < LEN")
    }

    fn wire_key_to_slot(key: Self::WireKey) -> Option<usize> {
        group_slot_for_iana_id(key)
    }

    fn slot_to_description(slot: usize) -> Option<&'static str> {
        TlsParam::Group.index_to_description(slot)
    }

    #[cfg(test)]
    const TLS_PARAM: TlsParam = TlsParam::Group;
}

pub(crate) struct SignatureKind;

impl ParameterKind for SignatureKind {
    const LEN: usize = SIGNATURE_COUNT;
    type WireKey = u16;

    fn slot_to_wire_key(slot: usize) -> Self::WireKey {
        signature_iana_id(slot).expect("slot < LEN")
    }

    fn wire_key_to_slot(key: Self::WireKey) -> Option<usize> {
        signature_slot_for_iana_id(key)
    }

    fn slot_to_description(slot: usize) -> Option<&'static str> {
        TlsParam::SignatureScheme.index_to_description(slot)
    }

    #[cfg(test)]
    const TLS_PARAM: TlsParam = TlsParam::SignatureScheme;
}

/// Atomic-backed counter storage for one parameter kind.
///
/// A single heap slab of `K::LEN` `AtomicU64`s, allocated once at
/// construction. Hot path is one relaxed `fetch_add` on `slots[slot]`.
pub(crate) struct Counter<K: ParameterKind> {
    slots: Box<[AtomicU64]>,
    _k: PhantomData<K>,
}

impl<K: ParameterKind> Counter<K> {
    pub(crate) fn new() -> Self {
        let slots: Box<[AtomicU64]> = (0..K::LEN)
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            slots,
            _k: PhantomData,
        }
    }

    pub(crate) fn increment(&self, slot: usize) {
        if let Some(counter) = self.slots.get(slot) {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Snapshot current values. `&mut self` guarantees no concurrent writer,
    /// so relaxed loads are sufficient.
    pub(crate) fn freeze(&mut self) -> FrozenCounter<K> {
        let snapshot: Box<[u64]> = self
            .slots
            .iter()
            .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
            .collect();
        FrozenCounter {
            slots: snapshot,
            _k: PhantomData,
        }
    }
}

impl<K: ParameterKind> std::fmt::Debug for Counter<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = format!("Counter<{}>", std::any::type_name::<K>());
        let mut dbg = f.debug_struct(&name);
        for (slot, atomic) in self.slots.iter().enumerate() {
            let value = atomic.load(std::sync::atomic::Ordering::Relaxed);
            if value > 0 {
                dbg.field(&slot.to_string(), &value);
            }
        }
        dbg.finish()
    }
}

/// Exportable, immutable snapshot of a `Counter<K>`.
pub(crate) struct FrozenCounter<K: ParameterKind> {
    pub(super) slots: Box<[u64]>,
    pub(super) _k: PhantomData<K>,
}

impl<K: ParameterKind> std::fmt::Debug for FrozenCounter<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct SlotList<'a>(&'a [u64]);
        impl<'a> std::fmt::Debug for SlotList<'a> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_list().entries(self.0.iter()).finish()
            }
        }

        let name = format!("FrozenCounter<{}>", std::any::type_name::<K>());
        f.debug_struct(&name)
            .field("slots", &SlotList(&self.slots))
            .finish()
    }
}

impl<K: ParameterKind> FrozenCounter<K> {
    /// `(description, count)` pairs for non-zero slots, in slot order.
    pub(crate) fn iter_non_zero(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c > 0)
            .filter_map(|(slot, &c)| K::slot_to_description(slot).map(|name| (name, c)))
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
        K::TLS_PARAM
            .description_to_index(description)
            .and_then(|slot| self.slots.get(slot).copied())
            .unwrap_or(0)
    }
}

impl<K: ParameterKind> Clone for FrozenCounter<K> {
    fn clone(&self) -> Self {
        Self {
            slots: self.slots.clone(),
            _k: PhantomData,
        }
    }
}

impl<K: ParameterKind> PartialEq for FrozenCounter<K> {
    fn eq(&self, other: &Self) -> bool {
        self.slots == other.slots
    }
}

impl<K: ParameterKind> Default for FrozenCounter<K> {
    fn default() -> Self {
        Self {
            slots: vec![0u64; K::LEN].into_boxed_slice(),
            _k: PhantomData,
        }
    }
}

impl<K: ParameterKind> serde::Serialize for FrozenCounter<K> {
    /// Emit non-zero slots as a map keyed by IANA wire id. Pre-counting
    /// gives length-prefixed formats (CBOR, postcard) the exact pair count.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let non_zero_count = self.slots.iter().filter(|&&c| c > 0).count();
        let mut map = serializer.serialize_map(Some(non_zero_count))?;
        for (slot, &value) in self.slots.iter().enumerate() {
            if value > 0 {
                map.serialize_entry(&K::slot_to_wire_key(slot), &value)?;
            }
        }
        map.end()
    }
}

impl<'de, K: ParameterKind> serde::Deserialize<'de> for FrozenCounter<K> {
    /// Decode a map of `(WireKey, u64)` pairs. Missing slots default to 0;
    /// unknown keys are dropped and logged at `debug!`. Duplicate keys
    /// follow serde's last-wins policy.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor<K: ParameterKind>(PhantomData<K>);

        impl<'de, K: ParameterKind> serde::de::Visitor<'de> for MapVisitor<K> {
            type Value = FrozenCounter<K>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a map of (IANA wire key, u64) pairs")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut slots: Box<[u64]> = vec![0u64; K::LEN].into_boxed_slice();
                let mut unknown: Vec<K::WireKey> = Vec::new();
                while let Some((key, value)) = access.next_entry::<K::WireKey, u64>()? {
                    match K::wire_key_to_slot(key) {
                        Some(slot) => slots[slot] = value,
                        None => unknown.push(key),
                    }
                }
                if !unknown.is_empty() {
                    // Dropping unknown keys is the designed cross-version
                    // behavior. Debug level keeps it discoverable without
                    // generating sustained volume during normal operation.
                    tracing::debug!(
                        kind = std::any::type_name::<K>(),
                        unknown_count = unknown.len(),
                        unknown = ?unknown,
                        "FrozenCounter deserialize dropped unknown IANA ids",
                    );
                }
                Ok(FrozenCounter {
                    slots,
                    _k: PhantomData,
                })
            }
        }

        deserializer.deserialize_map(MapVisitor::<K>(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assert `wire_key_to_slot(slot_to_wire_key(slot)) == Some(slot)` for
    /// every slot of every kind.
    fn roundtrip<K: ParameterKind>() {
        for slot in 0..K::LEN {
            let wire = K::slot_to_wire_key(slot);
            assert_eq!(
                K::wire_key_to_slot(wire),
                Some(slot),
                "round-trip failed at slot {slot} for wire key {wire:?}",
            );
        }
    }

    #[test]
    fn version_kind_roundtrip() {
        roundtrip::<VersionKind>();
    }

    #[test]
    fn cipher_kind_roundtrip() {
        roundtrip::<CipherKind>();
    }

    #[test]
    fn group_kind_roundtrip() {
        roundtrip::<GroupKind>();
    }

    #[test]
    fn signature_kind_roundtrip() {
        roundtrip::<SignatureKind>();
    }

    #[test]
    fn counter_freeze_snapshots_slots() {
        let mut counter = Counter::<CipherKind>::new();
        for _ in 0..3 {
            counter.increment(2);
        }
        for _ in 0..2 {
            counter.increment(7);
        }

        let frozen = counter.freeze();

        assert_eq!(frozen.slots.len(), CipherKind::LEN);
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
        let mut counter = Counter::<CipherKind>::new();
        for _ in 0..3 {
            counter.increment(2);
        }
        for _ in 0..5 {
            counter.increment(7);
        }
        let frozen = counter.freeze();

        let pairs: Vec<(&'static str, u64)> = frozen.iter_non_zero().collect();

        let expected_slot_2 = TlsParam::Cipher.index_to_description(2).unwrap();
        let expected_slot_7 = TlsParam::Cipher.index_to_description(7).unwrap();

        assert_eq!(pairs, vec![(expected_slot_2, 3), (expected_slot_7, 5)]);
    }

    #[test]
    fn frozen_counter_serialize_json_emits_iana_keys() {
        // Slot 0 of CipherKind is TLS_AES_128_GCM_SHA256, IANA id 0x1301
        // (= 4865 decimal).
        let mut counter = Counter::<CipherKind>::new();
        for _ in 0..3 {
            counter.increment(0);
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
        assert!(CipherKind::wire_key_to_slot(65535).is_none());

        let json = r#"{"4865": 3, "65535": 7}"#;
        let decoded: FrozenCounter<CipherKind> = serde_json::from_str(json).unwrap();

        let mut expected_counter = Counter::<CipherKind>::new();
        for _ in 0..3 {
            expected_counter.increment(0);
        }
        let expected = expected_counter.freeze();

        assert_eq!(decoded, expected);
    }

    #[test]
    fn frozen_counter_deserialize_missing_slots_are_zero() {
        let decoded: FrozenCounter<CipherKind> = serde_json::from_str("{}").unwrap();

        assert_eq!(decoded, FrozenCounter::<CipherKind>::default());
    }
}

#[cfg(test)]
mod malformed {
    //! `Deserialize` on `FrozenCounter<K>` must return a descriptive serde
    //! error (not panic) when its input is syntactically invalid.

    use super::*;

    #[test]
    fn json_non_integer_key_returns_error() {
        let json = r#"{"foo": 42}"#;
        serde_json::from_str::<FrozenCounter<CipherKind>>(json).unwrap_err();
    }

    #[test]
    fn json_non_integer_value_returns_error() {
        let json = r#"{"4865": "not a number"}"#;
        serde_json::from_str::<FrozenCounter<CipherKind>>(json).unwrap_err();
    }
}
