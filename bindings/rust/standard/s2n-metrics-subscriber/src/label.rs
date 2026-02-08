use std::{
    collections::HashMap,
    fmt::Display,
    sync::{LazyLock, RwLock},
};

use crate::static_lists::TlsParam;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum State {
    Negotiated,
    // Supported, - not implemented yet :)
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Negotiated => write!(f, "negotiated"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MetricLabel {
    /// e.g. "TLS_AES_256_GCM_SHA384" or "mlkem1024"
    item: &'static str,
    parameter: TlsParam,
    state: State,
}

impl MetricLabel {
    fn new(item: &'static str, parameter: TlsParam, state: State) -> Self {
        Self {
            item,
            parameter,
            state,
        }
    }

    fn value(&self) -> String {
        format!("{}.{}.{}", self.parameter, self.state, self.item)
    }
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

    fn insert(&self, metric: MetricLabel) -> &'static str {
        let mut write_lock = self.0.write().unwrap();
        // it's important that we only leak _after_ we have acquired the write lock.
        // otherwise we might end up leaking extra copies of the metric label
        let label = metric.value().leak();
        write_lock.insert(metric, label);
        label
    }
}

/// lookup from metric to the prefixed string, e.g. "group.negotiated.secp256r1"
pub(crate) fn metric_label(item: &'static str, parameter: TlsParam, state: State) -> &'static str {
    static PREFIXER: LazyLock<MetricLabeller> = LazyLock::new(MetricLabeller::default);

    let key = MetricLabel::new(item, parameter, state);

    match PREFIXER.get(&key) {
        Some(label) => label,
        None => PREFIXER.insert(key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_output() {
        assert_eq!(
            metric_label(
                "TLS_AES_256_GCM_SHA384",
                TlsParam::Cipher,
                State::Negotiated
            ),
            "cipher.negotiated.TLS_AES_256_GCM_SHA384"
        );
    }
}
