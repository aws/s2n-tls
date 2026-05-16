// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fmt::Display,
    sync::{LazyLock, RwLock},
};

use crate::static_lists::TlsParam;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    Negotiated,
    Supported,
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Negotiated => write!(f, "negotiated"),
            State::Supported => write!(f, "supported"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MetricLabel {
    parameter: TlsParam,
    slot: usize,
    state: State,
}

#[derive(Debug, Default)]
struct MetricLabeller(RwLock<HashMap<MetricLabel, &'static str>>);

impl MetricLabeller {
    fn get(&self, metric: &MetricLabel) -> Option<&'static str> {
        self.0.read().unwrap().get(metric).map(|label| &**label)
    }

    fn insert(&self, metric: MetricLabel, value: String) -> &'static str {
        let mut write_lock = self.0.write().unwrap();
        let label = value.leak();
        write_lock.insert(metric, label);
        label
    }
}

pub fn metric_label<T>(slot: usize, item: T, parameter: TlsParam, state: State) -> &'static str
where
    T: Display,
{
    static PREFIXER: LazyLock<MetricLabeller> = LazyLock::new(MetricLabeller::default);

    let key = MetricLabel {
        parameter,
        slot,
        state,
    };

    match PREFIXER.get(&key) {
        Some(label) => label,
        None => PREFIXER.insert(key, format!("{parameter}.{state}.{item}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_lists::Cipher;

    #[test]
    fn label_output() {
        assert_eq!(
            metric_label(
                0,
                Cipher::TLS_AES_256_GCM_SHA384,
                TlsParam::Cipher,
                State::Negotiated,
            ),
            "cipher.negotiated.TLS_AES_256_GCM_SHA384"
        );
    }
}
