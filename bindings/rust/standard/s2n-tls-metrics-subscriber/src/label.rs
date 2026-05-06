// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fmt::Display,
    sync::{LazyLock, RwLock},
};

use crate::static_lists::{FiniteCounter, TlsParam};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum State {
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

/// Cache key keyed by IANA wire id so the cache type stays non-generic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MetricLabel {
    parameter: TlsParam,
    iana_id: u16,
    state: State,
}

/// We want all of our metrics counters to be prefixed, e.g. `group.negotiated.secp256r1`
/// This will allow much easier CloudWatch graphs, because you can say things like
/// "graph all `group.negotiated.*` metrics"
///
/// metrique needs the string to be static, so we deliberately "leak" the data.
///
/// This is acceptable because it's just a finite set of values.
#[derive(Debug, Default)]
struct MetricLabeller(RwLock<HashMap<MetricLabel, &'static str>>);

impl MetricLabeller {
    fn get(&self, metric: &MetricLabel) -> Option<&'static str> {
        self.0.read().unwrap().get(metric).map(|label| &**label)
    }

    fn insert(&self, metric: MetricLabel, value: String) -> &'static str {
        let mut write_lock = self.0.write().unwrap();
        // it's important that we only leak _after_ we have acquired the write lock.
        // otherwise we might end up leaking extra copies of the metric label
        let label = value.leak();
        write_lock.insert(metric, label);
        label
    }
}

/// lookup from metric to the prefixed string, e.g. "group.negotiated.secp256r1"
pub(crate) fn metric_label<const N: usize, T: FiniteCounter<N>>(
    item: T,
    parameter: TlsParam,
    state: State,
) -> &'static str {
    static PREFIXER: LazyLock<MetricLabeller> = LazyLock::new(MetricLabeller::default);

    let key = MetricLabel {
        parameter,
        iana_id: item.iana_id(),
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
                Cipher::TLS_AES_256_GCM_SHA384,
                TlsParam::Cipher,
                State::Negotiated,
            ),
            "cipher.negotiated.TLS_AES_256_GCM_SHA384"
        );
    }
}
