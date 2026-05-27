// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Allocation regression gate for [`AggregatedMetricsSubscriber`].
//!
//! Same shape as `bindings/rust/standard/integration/tests/memory.rs`:
//! `dhat::Alloc` as the global allocator, hardcoded expected values, and
//! `fuzzy_equals` (±100 bytes) for byte-level drift. The test runs in
//! diff mode: the same handshake workload runs with and without the
//! subscriber attached, and we assert on the difference.

use s2n_tls::{
    config::Config,
    security::DEFAULT_TLS13,
    testing::{TestPair, build_config, config_builder},
};
use s2n_tls_metrics_subscriber::{
    AggregatedMetricsSubscriber, Attribution, MetricRecord, TelemetrySink,
};
use tabled::{Table, Tabled, settings::Style};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const FUZZY_TOLERANCE: i64 = 100;

fn fuzzy_equals(actual: i64, expected: i64) -> bool {
    (actual - expected).abs() <= FUZZY_TOLERANCE
}

/// No-op sink, so observed allocations are attributable to the subscriber
/// state machine and not to a sink implementation.
#[derive(Clone, Copy, Default)]
struct NullSink;

impl TelemetrySink for NullSink {
    fn export_record(&self, _record: &MetricRecord) {}
}

fn attribution() -> Attribution {
    Attribution {
        service: "memtest".to_owned(),
        resource: "memtest".to_owned(),
        component: "memtest".to_owned(),
    }
}

fn run_handshake(client_config: &Config, server_config: &Config) {
    let mut pair = TestPair::from_configs(client_config, server_config);
    pair.handshake().unwrap();
}

/// Pair of allocation counters, used both for measured deltas and for
/// expected budgets.
#[derive(Clone, Copy)]
struct AllocDelta {
    blocks: i64,
    bytes: i64,
}

impl AllocDelta {
    fn from_total_delta(before: &dhat::HeapStats, after: &dhat::HeapStats) -> Self {
        Self {
            blocks: (after.total_blocks - before.total_blocks) as i64,
            bytes: (after.total_bytes - before.total_bytes) as i64,
        }
    }

    fn from_curr_delta(before: &dhat::HeapStats, after: &dhat::HeapStats) -> Self {
        Self {
            blocks: after.curr_blocks as i64 - before.curr_blocks as i64,
            bytes: after.curr_bytes as i64 - before.curr_bytes as i64,
        }
    }

    fn sub(&self, other: &Self) -> Self {
        Self {
            blocks: self.blocks - other.blocks,
            bytes: self.bytes - other.bytes,
        }
    }
}

/// Run `work` `n` times and return the cumulative allocation delta.
fn measure(n: i64, work: impl Fn()) -> AllocDelta {
    let before = dhat::HeapStats::get();
    for _ in 0..n {
        work();
    }
    let after = dhat::HeapStats::get();
    AllocDelta::from_total_delta(&before, &after)
}

#[derive(Tabled)]
struct BudgetRow {
    phase: &'static str,
    metric: &'static str,
    expected: i64,
    observed: i64,
    delta: i64,
}

impl BudgetRow {
    fn pair(phase: &'static str, expected: AllocDelta, observed: AllocDelta) -> [Self; 2] {
        [
            Self {
                phase,
                metric: "blocks",
                expected: expected.blocks,
                observed: observed.blocks,
                delta: observed.blocks - expected.blocks,
            },
            Self {
                phase,
                metric: "bytes",
                expected: expected.bytes,
                observed: observed.bytes,
                delta: observed.bytes - expected.bytes,
            },
        ]
    }
}

#[test]
fn subscriber_allocation_budget() {
    let _profiler = dhat::Profiler::builder().testing().build();

    // N: large enough to amortize one-off allocations (e.g., std mpsc grows
    // its node arena in 32-slot chunks), small enough to keep the test under
    // a few seconds with dhat intercepting every malloc.
    const N: i64 = 200;
    // WARMUP: pre-runs each path so allocator pools and lazy-init don't
    // count against the measurement windows.
    const WARMUP: i64 = 50;

    // Block counts are deterministic per code path so we use strict equality;
    // byte counts can drift with capacity rounding so we use fuzzy_equals.
    const HOT_PATH: AllocDelta = AllocDelta {
        blocks: N * 40,
        bytes: N * 1720,
    };

    // The +(N + 31) / 32 term tracks std mpsc growing its node arena in
    // 32-slot chunks (i.e. ceil(N / 32) extra block allocations).
    //
    // Bytes scale with `sizeof(HandshakeRecordInProgress)` (per-flush
    // `Arc::new`) and `sizeof(FrozenHandshakeRecord)` (per-flush mpsc
    // node), so adding fields to either type bumps this number by
    // roughly (field_size * 2) * N.
    const EXPORT: AllocDelta = AllocDelta {
        blocks: N * 4 + (N + 31) / 32,
        bytes: 512_928,
    };

    // Subscriber state is fixed-size, so nothing should be retained across
    // measurement phases beyond what was already alive at setup time.
    const RETAINED: AllocDelta = AllocDelta {
        blocks: 0,
        bytes: 0,
    };

    let client_config = build_config(&DEFAULT_TLS13).unwrap();
    let server_config_baseline = config_builder(&DEFAULT_TLS13).unwrap().build().unwrap();
    let subscriber = AggregatedMetricsSubscriber::new(NullSink, attribution());
    let server_config_with_sub = {
        let mut builder = config_builder(&DEFAULT_TLS13).unwrap();
        builder.set_event_subscriber(subscriber.clone()).unwrap();
        builder.build().unwrap()
    };

    // Warmup pays one-shot lazy-init outside the measurement windows.
    measure(WARMUP, || {
        run_handshake(&client_config, &server_config_baseline)
    });
    measure(WARMUP, || {
        run_handshake(&client_config, &server_config_with_sub)
    });
    measure(WARMUP, || subscriber.finish_record());

    // Live heap right after setup + warmup: anything alive here (TLS
    // configs, subscriber state, channel arena) is the test's "rest"
    // memory and should not grow as the measurement phases run.
    let live_after_setup = dhat::HeapStats::get();

    let baseline = measure(N, || run_handshake(&client_config, &server_config_baseline));
    let with_sub = measure(N, || run_handshake(&client_config, &server_config_with_sub));
    let hot_path = with_sub.sub(&baseline);

    let export = measure(N, || subscriber.finish_record());

    let live_after_phases = dhat::HeapStats::get();
    let retained = AllocDelta::from_curr_delta(&live_after_setup, &live_after_phases);

    // Print the table before assertions. Cargo captures stdout by default,
    // so this surfaces in CI logs only on failure — same behavior as
    // `integration/tests/memory.rs`.
    let rows: Vec<BudgetRow> = [
        BudgetRow::pair("hot path", HOT_PATH, hot_path),
        BudgetRow::pair("export", EXPORT, export),
        BudgetRow::pair("retained", RETAINED, retained),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut table = Table::new(rows);
    table.with(Style::markdown());
    println!("{table}");

    assert_eq!(hot_path.blocks, HOT_PATH.blocks);
    assert!(fuzzy_equals(hot_path.bytes, HOT_PATH.bytes));
    assert_eq!(export.blocks, EXPORT.blocks);
    assert!(fuzzy_equals(export.bytes, EXPORT.bytes));
    assert_eq!(retained.blocks, RETAINED.blocks);
    assert_eq!(retained.bytes, RETAINED.bytes);
}
