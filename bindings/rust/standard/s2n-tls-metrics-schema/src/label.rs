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

/// Cache key keyed by slot index so the cache type stays non-generic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TelemetryLabel {
    prefix: &'static str,
    counter_slot: usize,
}

/// We want all of our metrics counters to be prefixed, e.g. `group.negotiated.secp256r1`
/// This will allow much easier CloudWatch graphs, because you can say things like
/// "graph all `group.negotiated.*` metrics"
///
/// metrique needs the string to be static, so we deliberately "leak" the data.
///
/// This is acceptable because it's just a finite set of values.
#[derive(Debug, Default)]
struct TelemetryLabeller(RwLock<HashMap<TelemetryLabel, &'static str>>);

impl TelemetryLabeller {
    fn get(&self, telemetry: &TelemetryLabel) -> Option<&'static str> {
        self.0.read().unwrap().get(telemetry).map(|label| &**label)
    }

    fn insert(&self, telemetry: &TelemetryLabel, value: String) -> &'static str {
        let mut write_lock = self.0.write().unwrap();
        // it's important that we only leak _after_ we have acquired the write lock.
        // otherwise we might end up leaking extra copies of the metric label
        let label = value.leak();
        write_lock.insert(*telemetry, label);
        label
    }
}

/// lookup from metric to the prefixed string, e.g. "group.negotiated.secp256r1"
pub fn telemetry_label<T>(counter_slot: usize, item: T, prefix: &'static str) -> &'static str
where
    T: Display,
{
    static PREFIXER: LazyLock<TelemetryLabeller> = LazyLock::new(TelemetryLabeller::default);

    let key = TelemetryLabel {
        prefix,
        counter_slot,
    };

    match PREFIXER.get(&key) {
        Some(label) => label,
        None => PREFIXER.insert(&key, format!("{prefix}.{item}")),
    }
}

/// a helper function to create the prefix for (param, state) tuples
pub fn telemetry_prefix(param: TlsParam, state: State) -> &'static str {
    let prefix = match (param, state) {
        (TlsParam::Version, State::Negotiated) => "version.negotiated",
        (TlsParam::Version, State::Supported) => "version.supported",
        (TlsParam::Cipher, State::Negotiated) => "cipher.negotiated",
        (TlsParam::Cipher, State::Supported) => "cipher.supported",
        (TlsParam::Group, State::Negotiated) => "group.negotiated",
        (TlsParam::Group, State::Supported) => "group.supported",
        (TlsParam::SignatureScheme, State::Negotiated) => "signature_scheme.negotiated",
        (TlsParam::SignatureScheme, State::Supported) => "signature_scheme.supported",
    };
    // this debug assert makes sure that our labels match the Display implementation.
    // We don't directly use Display because that requires an allocation. We could
    // introduce a static display trait, but that feels like overkill :)
    debug_assert_eq!(format!("{param}.{state}"), prefix);
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_lists::Cipher;

    #[test]
    fn label_output() {
        assert_eq!(
            telemetry_label(
                0,
                Cipher::TLS_AES_256_GCM_SHA384,
                telemetry_prefix(TlsParam::Cipher, State::Negotiated),
            ),
            "cipher.negotiated.TLS_AES_256_GCM_SHA384"
        );
    }
}
