// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    marker::PhantomData,
    sync::atomic::{AtomicU64, Ordering},
};

use s2n_tls_metrics_schema::{counter::FrozenCounter, static_lists::FiniteCounter};

/// Atomic-backed counter storage for one parameter kind.
pub(crate) struct Counter<const N: usize, T: FiniteCounter<N>> {
    slots: [AtomicU64; N],
    element: PhantomData<T>,
}

impl<const N: usize, T: FiniteCounter<N>> Counter<N, T> {
    pub(crate) fn new() -> Self {
        let slots: [AtomicU64; N] = [0u64; N].map(AtomicU64::new);
        Self {
            slots,
            element: PhantomData,
        }
    }

    pub(crate) fn increment(&self, element: &T) {
        if let Some(counter) = element
            .slot_from_key()
            .and_then(|slot| self.slots.get(slot))
        {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn freeze(&mut self) -> FrozenCounter<N, T> {
        FrozenCounter::from_slots(std::array::from_fn(|i| {
            self.slots[i].load(Ordering::Relaxed)
        }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use s2n_tls_metrics_schema::static_lists::{CIPHER_COUNT, Cipher};

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

        assert_eq!(frozen.slots().len(), CIPHER_COUNT);
        assert_eq!(frozen.slots()[2], 3);
        assert_eq!(frozen.slots()[7], 2);
        for (i, &value) in frozen.slots().iter().enumerate() {
            if i == 2 || i == 7 {
                continue;
            }
            assert_eq!(value, 0, "slot {i} expected 0, got {value}");
        }
    }
}
