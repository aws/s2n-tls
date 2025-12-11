use std::{
    collections::HashMap,
    ffi::CStr,
    fmt::Debug,
    hash::Hash,
    io,
    sync::{
        atomic::AtomicU64,
        mpsc::{Receiver, Sender},
        Arc, LazyLock, Mutex,
    },
    time::{Duration, Instant, SystemTime},
};

use aws_sdk_cloudwatchlogs::{types::InputLogEvent, Client};
use metrique::{unit::Count, unit_of_work::metrics, ServiceMetrics};
use metrique_writer::{sink::AttachHandle, AttachGlobalEntrySinkExt, FormatExt, GlobalEntrySink};
use metrique_writer_format_emf::Emf;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::MakeWriter;

use crate::record::{FrozenS2NMetricRecord, MetricWithAttribution};

use metrique_writer::format::Format;



/// This is a very inefficient metric uploader for CloudWatch
///
/// You MUST poll [`CloudWatchExporter::try_write`] to actually write events to
/// cloudwatch. It does not happen in the background/automatically.
///
/// This is done to make sure that all events from short lived tests are getting
/// flushed.
pub struct CloudWatchExporter {
    /// The cloudwatch logs client, used to "put-metric-events"
    record_receiver: std::sync::mpsc::Receiver<FrozenS2NMetricRecord>,
    pub resource: Option<String>,
    emf_formatter: Emf,
    cloudwatch_logs_client: Client,
}

impl CloudWatchExporter {
    pub async fn initialize(rx: Receiver<FrozenS2NMetricRecord>) -> Self {
        // load AWS credentials from the environments
        let config = aws_config::load_from_env().await;
        let client = aws_sdk_cloudwatchlogs::Client::new(&config);
        let emf = Emf::builder("tls/s2n-tls".to_string(), vec![vec![]]).build();

        CloudWatchExporter {
            cloudwatch_logs_client: client,
            resource: None,
            emf_formatter: emf,
            record_receiver: rx,
        }
    }

    fn current_timestamp() -> i64 {
        SystemTime::UNIX_EPOCH.elapsed().unwrap().as_millis() as i64
    }

    pub async fn try_write(&mut self) -> bool {
        if let Ok(record) = self.record_receiver.try_recv() {

            let emf_record = {
                let mut buffer = Vec::new();
                if let Some(resource) = self.resource.as_ref() {
                    let with_attribution = MetricWithAttribution::new(record, resource.clone());
                    self.emf_formatter.format(&with_attribution, &mut buffer).unwrap();
                } else {
                    self.emf_formatter.format(&record, &mut buffer).unwrap();
                }
                buffer
            };
            // let formatted = self.emf_formatter.format(&record);
            let event = InputLogEvent::builder()
                .message(String::from_utf8(emf_record).unwrap())
                .timestamp(Self::current_timestamp())
                .build()
                .unwrap();
            let result = self
                .cloudwatch_logs_client
                .put_log_events()
                .log_group_name("s2n-tls-metric-development")
                .log_stream_name("stream1")
                .log_events(event)
                .send()
                .await
                .unwrap();
            true
        } else {
            false
        }
    }
}

// impl EventSubscriber for CloudWatchExporter {
//     fn on_handshake_event(&self, event: &s2n_tls_sys::s2n_event_handshake) {
//         let handshake = HandshakeMetrics::from_event(event);
//         ServiceMetrics::append(handshake);
//         resumption.map(|event| ServiceMetrics::append(event));
//     }
// }

// pub struct RollingFileExporter(AttachHandle);

// impl RollingFileExporter {
//     fn service_metrics_init() -> Self {
//         let attach_handle = ServiceMetrics::attach_to_stream(
//             Emf::builder("tls/s2n-tls".to_string(), vec![vec![]])
//                 .build()
//                 .output_to_makewriter(RollingFileAppender::new(
//                     Rotation::HOURLY,
//                     "logs",
//                     "s2n.log",
//                 )),
//         );
//         RollingFileExporter(attach_handle)
//     }
// }

// impl EventSubscriber for RollingFileExporter {
//     fn on_handshake_event(&self, event: &s2n_tls_sys::s2n_event_handshake) {
//         let handshake = HandshakeMetrics::from_event(event);
//         let resumption = ResumptionMetrics::from_event(&event.resumption_event);
//         ServiceMetrics::append(handshake);
//         resumption.map(|event| ServiceMetrics::append(event));
//     }
// }

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use s2n_tls::{
        security::{self, Policy},
        testing::{build_config, config_builder, TestPair},
    };

    // #[test]
    // fn event_emissions() {
    //     let subscriber = TestSubscriber::default();
    //     let invoked = subscriber.invoked.clone();
    //     let mut server_config = config_builder(&security::DEFAULT_TLS13).unwrap();
    //     server_config.set_event_subscriber(subscriber).unwrap();
    //     let server_config = server_config.build().unwrap();

    //     let client_config = build_config(&security::DEFAULT_TLS13).unwrap();
    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     assert_eq!(invoked.load(Ordering::Relaxed), 1);

    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     assert_eq!(invoked.load(Ordering::Relaxed), 2);
    //     assert!(false);
    // }

    // #[test]
    // fn logging_events() {
    //     let subscriber = RollingFileExporter::service_metrics_init();
    //     let mut server_config = config_builder(&security::DEFAULT_TLS13).unwrap();
    //     server_config.set_event_subscriber(subscriber).unwrap();
    //     let server_config = server_config.build().unwrap();

    //     let client_config = build_config(&security::DEFAULT_TLS13).unwrap();
    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();

    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();

    //     assert!(false);
    // }

    // #[tokio::test]
    // async fn cloudwatch_events() {
    //     let subscriber = CloudWatchExporter::initialize().await;
    //     let subscriber_handle = subscriber.clone();
    //     let mut server_config = config_builder(&security::DEFAULT_TLS13).unwrap();
    //     server_config
    //         .set_event_subscriber(subscriber_handle)
    //         .unwrap();
    //     let server_config = server_config.build().unwrap();

    //     let client_configs = [
    //         build_config(&security::DEFAULT_TLS13).unwrap(),
    //         build_config(&security::DEFAULT_TLS13).unwrap(),
    //         build_config(&Policy::from_version("default_pq").unwrap()).unwrap(),
    //     ];

    //     let client_config = build_config(&security::DEFAULT_TLS13).unwrap();
    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     subscriber.try_write().await;

    //     let mut test_pair = TestPair::from_configs(&client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     subscriber.try_write().await;

    //     let tls12_client_config = build_config(&security::DEFAULT).unwrap();
    //     let mut test_pair = TestPair::from_configs(&tls12_client_config, &server_config);
    //     test_pair.handshake().unwrap();
    //     subscriber.try_write().await;

    //     std::thread::sleep(Duration::from_secs(1));
    //     assert!(false);
    // }

    // #[tokio::test]
    // async fn cloudwatch_emission() {
    //     let config = aws_config::load_from_env().await;
    //     let client = aws_sdk_cloudwatchlogs::Client::new(&config);
    //     client.put_log_events().
    // }
}
