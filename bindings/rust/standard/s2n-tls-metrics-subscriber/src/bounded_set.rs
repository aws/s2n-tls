// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, ops::Deref, sync::RwLock};

use s2n_tls_metrics_schema::bounded_set::FrozenBoundedStringSet;

#[derive(Debug)]
pub(crate) struct BoundedStringSet {
    storage: RwLock<HashSet<String>>,
}

impl Default for BoundedStringSet {
    fn default() -> Self {
        Self {
            // set capacity to 10 to minimize allocations
            storage: RwLock::new(HashSet::with_capacity(Self::MAX_STORAGE)),
        }
    }
}

impl BoundedStringSet {
    const MAX_STORAGE: usize = 10;
    /// record the existence of a value.
    ///
    /// This will be a no-op if the item is already in the set
    pub fn record(&self, item: &str) {
        let should_insert = { Self::should_insert(&self.storage.read().unwrap(), item) };

        if should_insert {
            // acquire write lock
            let mut write_set = self.storage.write().unwrap();
            // recheck, because things might have changed
            if Self::should_insert(&write_set, item) {
                write_set.insert(item.to_owned());
            }
        }
    }

    fn should_insert<T: Deref<Target = HashSet<String>>>(set: &T, element: &str) -> bool {
        !set.contains(element) && set.len() < Self::MAX_STORAGE
    }

    pub fn freeze(&self) -> FrozenBoundedStringSet {
        let storage = self.storage.read().unwrap();
        if storage.len() >= Self::MAX_STORAGE {
            FrozenBoundedStringSet::TooMany
        } else {
            FrozenBoundedStringSet::Entries(storage.iter().cloned().collect())
        }
    }
}
