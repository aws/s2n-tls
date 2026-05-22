// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pluggable detection of synthetic traffic (scanners, health-checks, internal
//! load tests, etc.) so consumers can filter such handshakes out of their
//! metrics without baking the detection logic into this crate.
//!
//! Each detector receives the parsed [`ClientHello`] and returns whether the
//! handshake should be counted as synthetic. When a detector returns `true`,
//! [`AggregatedMetricsSubscriber`] increments only the `synthetic_traffic_count`
//! field on the in-progress record; every other counter (including
//! `handshake_count`) is left untouched, so each metric can be read directly
//! as a real traffic figure.
//!
//! [`ClientHello`]: s2n_tls::client_hello::ClientHello
//! [`AggregatedMetricsSubscriber`]: crate::AggregatedMetricsSubscriber

use s2n_tls::client_hello::ClientHello;

/// Returns `true` for handshakes whose [`ClientHello`] should be counted as
/// synthetic traffic.
///
/// Implementations are called on the handshake-completion path, so they should
/// be cheap. Allocations and locks should be avoided.
pub trait SyntheticTrafficDetector: Send + Sync + 'static {
    fn is_synthetic(&self, client_hello: &ClientHello) -> bool;
}

/// Blanket impl so callers can pass a closure (wrapped in `Box::new`), for example:
///
/// ```ignore
/// subscriber.with_synthetic_traffic_detector(Box::new(|ch: &ClientHello| {
///     ch.random().map(|r| r.starts_with(b"my-marker")).unwrap_or(false)
/// }));
/// ```
impl<F> SyntheticTrafficDetector for F
where
    F: Fn(&ClientHello) -> bool + Send + Sync + 'static,
{
    fn is_synthetic(&self, client_hello: &ClientHello) -> bool {
        (self)(client_hello)
    }
}
