// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashSet,
    sync::{
        RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use s2n_tls_metrics_schema::bounded_set::FrozenBoundedStringSet;

#[derive(Debug)]
pub(crate) struct BoundedStringSet {
    storage: RwLock<HashSet<String>>,
    overflow: AtomicBool,
}

impl Default for BoundedStringSet {
    fn default() -> Self {
        Self {
            // set capacity to 10 to minimize allocations
            storage: RwLock::new(HashSet::with_capacity(Self::MAX_STORAGE)),
            overflow: AtomicBool::new(false),
        }
    }
}

impl BoundedStringSet {
    pub(crate) const MAX_STORAGE: usize = 10;
    /// record the existence of a value.
    ///
    /// This will be a no-op if the item is already in the set
    pub fn record(&self, item: &str) {
        let storage = self.storage.read().unwrap();
        if storage.contains(item) {
            return;
        }
        if storage.len() >= Self::MAX_STORAGE {
            self.overflow.store(true, Ordering::Relaxed);
            return;
        }
        drop(storage);

        // acquire write lock
        let mut write_set = self.storage.write().unwrap();
        if write_set.contains(item) {
            return;
        }
        if write_set.len() >= Self::MAX_STORAGE {
            self.overflow.store(true, Ordering::Relaxed);
            return;
        }
        write_set.insert(item.to_owned());
    }

    pub fn freeze(&self) -> FrozenBoundedStringSet {
        if self.overflow.load(Ordering::Relaxed) {
            FrozenBoundedStringSet::TooMany
        } else {
            let storage = self.storage.read().unwrap();
            FrozenBoundedStringSet::Entries(storage.iter().cloned().collect())
        }
    }
}
