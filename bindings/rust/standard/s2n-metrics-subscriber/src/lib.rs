use std::{
    alloc::System,
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender},
        Arc, Mutex,
    },
    time::SystemTime,
};

mod static_lists;

use s2n_tls::events::EventSubscriber;

use crate::static_lists::{CIPHERS_AVAILABLE_IN_S2N, GROUPS_AVAILABLE_IN_S2N};

const GROUP_COUNT: usize = GROUPS_AVAILABLE_IN_S2N.len();
const CIPHER_COUNT: usize = CIPHERS_AVAILABLE_IN_S2N.len();
const SIGNATURE_SCHEME_COUNT: usize = 5;
const SIG_HASH_COUNT: usize = 5;
const PROTOCOL_VERSION_COUNT: usize = 5;

/// https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_StatisticSet.html
#[derive(Debug, Default)]
struct StatisticSet {
    sum: AtomicU64,
    min: AtomicU64,
    max: AtomicU64,
    sample_count: AtomicU64,
}

impl StatisticSet {
    pub fn update(&self, new_measurement: u64) {
        self.sum.fetch_add(new_measurement, Ordering::Relaxed);
        self.min.fetch_min(new_measurement, Ordering::Relaxed);
        self.max.fetch_max(new_measurement, Ordering::Relaxed);
        self.sample_count.fetch_add(1, Ordering::Relaxed);
    }

    fn freeze(&self) -> FrozenStatisticSet {
        FrozenStatisticSet {
            sum: self.sum.load(Ordering::Relaxed),
            min: self.min.load(Ordering::Relaxed),
            max: self.max.load(Ordering::Relaxed),
            sample_count: self.sample_count.load(Ordering::Relaxed),
        }
    }

    fn clear_statistics(&self) {
        self.sum.store(0, Ordering::Relaxed);
        self.min.store(0, Ordering::Relaxed);
        self.max.store(0, Ordering::Relaxed);
        self.sample_count.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Default)]
struct FrozenStatisticSet {
    sum: u64,
    min: u64,
    max: u64,
    sample_count: u64,
}

// TODO, this should have +1 for unrecognized things
#[derive(Debug)]
struct S2NMetricRecord {
    // groups
    groups: [AtomicU64; GROUP_COUNT],
    // ciphers
    ciphers: [AtomicU64; CIPHER_COUNT],
    // signature schemes
    signature_scheme: [AtomicU64; SIGNATURE_SCHEME_COUNT],
    // signatures
    sig_hash: [AtomicU64; SIG_HASH_COUNT],
    // protocol versions
    protocols: [AtomicU64; PROTOCOL_VERSION_COUNT],

    /// sum of handshake duration
    handshake_duration_us: StatisticSet,
    /// sum of handshake compute
    handshake_compute: StatisticSet,
}

impl Default for S2NMetricRecord {
    fn default() -> Self {
        let ciphers= [0; CIPHER_COUNT].map(|_| AtomicU64::default());
        Self {
            groups: Default::default(),
            ciphers,
            signature_scheme: Default::default(),
            sig_hash: Default::default(),
            protocols: Default::default(),
            handshake_duration_us: Default::default(),
            handshake_compute: Default::default(),
        }
    }
}

impl S2NMetricRecord {
    /// make a copy of this record to be exported, and zero all entries
    fn freeze(&self) -> FrozenS2NMetricRecord {
        let groups = self
            .groups
            .each_ref()
            .map(|counter| counter.load(Ordering::Relaxed));
        let ciphers = self
            .ciphers
            .each_ref()
            .map(|counter| counter.load(Ordering::Relaxed));
        let signature_scheme = self
            .signature_scheme
            .each_ref()
            .map(|counter| counter.load(Ordering::Relaxed));
        let sig_hash = self
            .sig_hash
            .each_ref()
            .map(|counter| counter.load(Ordering::Relaxed));
        let protocols = self
            .protocols
            .each_ref()
            .map(|counter| counter.load(Ordering::Relaxed));

        let frozen_record = FrozenS2NMetricRecord {
            freeze_time: SystemTime::now(),
            groups,
            ciphers,
            signature_scheme,
            sig_hash,
            protocols,
            handshake_duration: self.handshake_duration_us.freeze(),
            handshake_compute: self.handshake_compute.freeze(),
        };

        self.adjust_for_export(&frozen_record);
        frozen_record
    }

    /// Not that the metric record is _not_ locked during this action, so there
    /// is not guarantee that all values will be zero upon the return of this function
    fn adjust_for_export(&self, frozen: &FrozenS2NMetricRecord) {
        self.groups.iter().zip(frozen.groups.iter()).for_each(
            |(record_counter, frozen_counter)| {
                record_counter.fetch_sub(*frozen_counter, Ordering::Relaxed);
            },
        );

        let groups = self.groups.iter().zip(frozen.groups.iter());
        let cipher = self.ciphers.iter().zip(frozen.ciphers.iter());
        let signature_scheme = self
            .signature_scheme
            .iter()
            .zip(frozen.signature_scheme.iter());
        let sig_hash = self.sig_hash.iter().zip(frozen.sig_hash.iter());
        let protocols = self.protocols.iter().zip(frozen.protocols.iter());

        groups
            .chain(cipher)
            .chain(signature_scheme)
            .chain(sig_hash)
            .chain(protocols)
            .for_each(|(metric_counter, frozen_counter)| {
                metric_counter.fetch_sub(*frozen_counter, Ordering::Relaxed);
            });
    }
}

#[derive(Debug)]
struct FrozenS2NMetricRecord {
    pub freeze_time: SystemTime,
    // groups
    pub groups: [u64; GROUP_COUNT],
    // ciphers
    pub ciphers: [u64; CIPHER_COUNT],
    // signature schemes
    pub signature_scheme: [u64; SIGNATURE_SCHEME_COUNT],
    // signatures
    pub sig_hash: [u64; SIG_HASH_COUNT],
    // protocol versions
    pub protocols: [u64; PROTOCOL_VERSION_COUNT],

    pub handshake_duration: FrozenStatisticSet,
    pub handshake_compute: FrozenStatisticSet,
}

#[derive(Debug, Clone)]
pub struct AggregatedMetricsSubscriber {
    current_record: Arc<S2NMetricRecord>,
    sender: Arc<Mutex<SyncSender<FrozenS2NMetricRecord>>>,
}

impl AggregatedMetricsSubscriber {
    const CHANNEL_CAPACITY: usize = 1024;

    fn new() -> (Self, Receiver<FrozenS2NMetricRecord>) {
        let (tx, rx) = std::sync::mpsc::sync_channel(Self::CHANNEL_CAPACITY);
        let record = S2NMetricRecord::default();
        let value = Self {
            current_record: Arc::new(record),
            sender: Arc::new(Mutex::new(tx)),
        };
        (value, rx)
    }

    /// export the record to the channel, and reset all counters to zero.
    fn export(&self) {
        let export_lock = self.sender.lock().unwrap();
        let record = self.current_record.freeze();
        let result = export_lock.send(record);
        if result.is_err() {
            tracing::warn!("channel full, dropping metric record");
        }
    }
}

impl EventSubscriber for AggregatedMetricsSubscriber {
    fn on_handshake_event(
        &self,
        connection: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) {
        self.current_record
            .handshake_compute
            .update(event.synchronous_time().as_micros() as u64);
        self.current_record
            .handshake_duration_us
            .update(event.duration().as_micros() as u64);
        tracing::debug!("handshake event invoked : {event:?}");
    }
}

trait Recorder {
    /// export a record to some sink.
    ///
    /// E.g. this might call CloudWatch
    fn export(&mut self, metric_record: FrozenS2NMetricRecord);
}

struct CloudWatchPutMetricDataExporter {}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use s2n_tls::{
        security::{Policy, DEFAULT_TLS13},
        testing::{build_config, config_builder, TestPair},
    };

    use super::*;

    #[test]
    fn it_works() {
        let (subscriber, rx) = AggregatedMetricsSubscriber::new();
        let subscriber_handle = subscriber.clone();
        let server_config = {
            let mut config = config_builder(&DEFAULT_TLS13).unwrap();
            config.set_event_subscriber(subscriber).unwrap();
            config.build().unwrap()
        };
        let client_config = build_config(&DEFAULT_TLS13).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();

        assert!(rx.try_recv().is_err());
        subscriber_handle.export();
        let event = rx.recv().unwrap();
        println!("{event:?}");
    }

    #[test]
    fn iter() {
        let hashmap: HashMap<u16, AtomicU64> = HashMap::new();
    }
}
