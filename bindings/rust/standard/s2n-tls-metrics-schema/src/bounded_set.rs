// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FrozenBoundedStringSet {
    /// more than 10 values were supplied
    TooMany,
    Entries(BTreeSet<String>),
}

impl Default for FrozenBoundedStringSet {
    fn default() -> Self {
        FrozenBoundedStringSet::Entries(BTreeSet::new())
    }
}
