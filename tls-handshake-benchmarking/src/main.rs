// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Handshake timing tool — runs TLS 1.3 handshakes via s2n-tls and prints
//! per-message timing data, then serializes results to JSON.
//!
//! The C library emits a single monotonic timestamp per dispatched message
//! (a "checkpoint"). This harness collects checkpoints into per-iteration
//! batches, computes per-message durations as deltas between consecutive
//! checkpoints, and writes the results to JSON in the same shape this tool
//! produced before the redesign.
//!
//! Usage: handshake-timing [rsa2048|rsa3072|rsa4096|ecdsa256|ecdsa384] [output.json]

use std::{collections::BTreeMap, sync::Arc, sync::Mutex, time::Instant};

use rcgen::{
    CertificateParams, KeyPair, RsaKeySize, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_RSA_SHA256,
};
use serde::Serialize;

use s2n_tls::{
    callbacks::VerifyHostNameCallback,
    config::Builder,
    connection::Connection,
    events::{EventSubscriber, HandshakeEvent, TimingCheckpoint},
    testing::{TestPair, LIFOSessionResumption},
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::timing::{
    Direction as RustlsDirection, TimingCheckpoint as RustlsCheckpoint,
    TimingSubscriber as RustlsTimingSubscriber,
};

// ============================================================================
// Output data model — kept identical to the pre-redesign shape so existing
// tooling (visualize.py, dashboards) continues to work.
// ============================================================================

#[derive(Serialize, Clone)]
struct MeasurementRecord {
    implementation: String,
    handshake_type: String,
    iteration: u64,
    message_name: String,
    role: String,
    /// "read" (processing a received message) or "write" (producing a sent one).
    /// Comparisons key on (message_name, role, direction); only role+direction
    /// matches measure the same work across implementations.
    direction: String,
    duration_ns: u64,
    /// Wall-clock ordering (ns since harness epoch) for timeline interleaving.
    wall_ns: u64,
}

#[derive(Serialize, Clone)]
struct MessageStats {
    mean_ns: f64,
    stddev_ns: f64,
    cv_percent: f64,
}

#[derive(Serialize)]
struct Metadata {
    cpu_model: String,
    warmup_iterations: u64,
    measurement_iterations: u64,
    cert_type: String,
    s2n_mean_us: f64,
    rustls_mean_us: f64,
}

#[derive(Serialize)]
struct OutputFile {
    metadata: Metadata,
    measurements: Vec<MeasurementRecord>,
    reproducibility: BTreeMap<String, MessageStats>,
}

const HANDSHAKE_ORDER: &[&str] = &[
    "CLIENT_HELLO",
    "SERVER_HELLO",
    "SERVER_CHANGE_CIPHER_SPEC",
    "ENCRYPTED_EXTENSIONS",
    "SERVER_CERT_REQ",
    "SERVER_CERT",
    "SERVER_CERT_VERIFY",
    "SERVER_FINISHED",
    "CLIENT_CERT",
    "CLIENT_CERT_VERIFY",
    "CLIENT_CHANGE_CIPHER_SPEC",
    "CLIENT_FINISHED",
    "NEGOTIATE_END",
];

// ============================================================================
// Timing subscriber
//
// The C library emits checkpoints (name + monotonic timestamp). The harness
// stores the raw checkpoints first, then converts them to per-message
// durations after each handshake completes by computing deltas between
// consecutive checkpoints.
// ============================================================================

#[derive(Debug, Clone)]
struct RawCheckpoint {
    name: String,
    role: String,
    timestamp_ns: u64,
    /// "read" (inbound/processed) or "write" (outbound/produced).
    direction: String,
    /// Wall-clock capture time (ns since a shared harness epoch). Used for
    /// ordering checkpoints from both sides onto one global timeline (even for
    /// rustls where `timestamp_ns` is per-connection-relative and can't be
    /// merged across sides).
    wall_ns: u64,
}

/// Shared harness epoch for wall-clock ordering.
static WALL_EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn wall_now() -> u64 {
    let epoch = WALL_EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_nanos() as u64
}

/// Global checkpoint buffer. Each handshake's checkpoints are appended in
/// order. After each handshake we walk the buffer, compute deltas, and
/// produce one MeasurementRecord per consecutive pair.
static CHECKPOINTS: Mutex<Vec<RawCheckpoint>> = Mutex::new(Vec::new());

struct TimingSubscriber;

impl EventSubscriber for TimingSubscriber {
    fn on_handshake_event(&self, _connection: &Connection, _event: &HandshakeEvent) {
        // The aggregate handshake event is not used by this tool.
    }

    fn on_timing_checkpoint(&self, _connection: &Connection, checkpoint: &TimingCheckpoint) {
        let name = checkpoint.name().to_string();
        let role = if checkpoint.is_server() {
            "server".to_string()
        } else {
            "client".to_string()
        };
        let direction = s2n_direction(&name, &role).to_string();
        let record = RawCheckpoint {
            name,
            role,
            timestamp_ns: checkpoint.timestamp_ns(),
            direction,
            wall_ns: wall_now(),
        };
        if let Ok(mut buf) = CHECKPOINTS.lock() {
            buf.push(record);
        }
    }
}

/// Direction of an s2n checkpoint. s2n's API doesn't tag read vs write, but it's
/// fully determined by (message_name, role) via the TLS 1.3 sender table: the
/// side that SENDS a message runs its "send" handler (write/produce), the side
/// that RECEIVES runs the "recv" handler (read/process). This matches rustls's
/// explicit Direction so comparisons can key on (name, role, direction).
fn s2n_direction(name: &str, role: &str) -> &'static str {
    match name {
        "RECORD_WRITE" => "write",
        "RECORD_READ" | "NEGOTIATE_START" | "NEGOTIATE_END" => "read",
        // Messages the client sends (server receives):
        "CLIENT_HELLO" | "CLIENT_CERT" | "CLIENT_CERT_VERIFY" | "CLIENT_FINISHED"
        | "CLIENT_CHANGE_CIPHER_SPEC" => {
            if role == "client" {
                "write"
            } else {
                "read"
            }
        }
        // Messages the server sends (client receives):
        "SERVER_HELLO" | "ENCRYPTED_EXTENSIONS" | "SERVER_CERT" | "SERVER_CERT_REQ"
        | "SERVER_CERT_VERIFY" | "SERVER_FINISHED" | "HELLO_RETRY_REQUEST"
        | "SERVER_CHANGE_CIPHER_SPEC" => {
            if role == "server" {
                "write"
            } else {
                "read"
            }
        }
        _ => "read",
    }
}

/// Convert a raw checkpoint buffer into per-message duration records (s2n-tls).
///
/// Uses the global timeline: all checkpoints in an iteration are sorted by
/// timestamp, and each message's duration is the delta from the immediately
/// preceding checkpoint (regardless of role). This is valid for s2n-tls
/// because both sides share one absolute monotonic clock, so client and
/// server checkpoints can be interleaved on a single timeline. This correctly
/// handles single-threaded cooperative I/O where one side's work happens
/// between the other side's checkpoints.
///
/// The first checkpoint per iteration (`NEGOTIATE_START`) is an anchor and
/// does not produce a duration record.
fn compute_durations_s2n(checkpoints: &[RawCheckpoint], iterations: u64) -> Vec<MeasurementRecord> {
    if checkpoints.is_empty() || iterations == 0 {
        return Vec::new();
    }

    let total = checkpoints.len() as u64;
    let per_handshake = total.checked_div(iterations).unwrap_or(0);
    if per_handshake == 0 {
        return Vec::new();
    }

    let mut records = Vec::new();
    for (idx, ckpt_chunk) in checkpoints.chunks(per_handshake as usize).enumerate() {
        let iteration = idx as u64;

        // Sort all checkpoints in this iteration by timestamp (global timeline).
        let mut sorted: Vec<&RawCheckpoint> = ckpt_chunk.iter().collect();
        sorted.sort_by_key(|c| c.timestamp_ns);

        // Walk the global timeline. Each message's duration is the delta from
        // the immediately preceding checkpoint, regardless of which side it
        // came from. This means cross-side handoff time is not inflated.
        for window in sorted.windows(2) {
            let prev = window[0];
            let curr = window[1];

            // Skip NEGOTIATE_START — it's only an anchor.
            if curr.name == "NEGOTIATE_START" {
                continue;
            }

            let duration_ns = curr.timestamp_ns.saturating_sub(prev.timestamp_ns);
            records.push(MeasurementRecord {
                implementation: "s2n-tls".to_string(),
                handshake_type: "tls13_full".to_string(),
                iteration,
                message_name: curr.name.clone(),
                role: curr.role.clone(),
                direction: curr.direction.clone(),
                duration_ns,
                wall_ns: curr.wall_ns,
            });
        }
    }
    records
}

/// Convert per-stream rustls checkpoints into per-message duration records.
///
/// rustls uses a *per-connection relative epoch* (each side's `NEGOTIATE_START`
/// is timestamp 0), so client and server streams are processed separately —
/// never merged onto one global timeline.
///
/// DELTA RULE (per rustls agent handoff, mirrors s2n's RECORD_READ boundary):
///  - For a READ (inbound) message, its processing cost is the delta from the
///    *immediately preceding RECORD_READ* checkpoint, NOT from the previous
///    message. The gap previous_message -> RECORD_READ is peer-wait (idle time
///    waiting for bytes) and must be excluded.
///  - WRITE (outbound) messages are emitted for coverage but their deltas are
///    NOT clean per-message costs (rustls batches a whole flight into one
///    handler). We record them tagged direction="write" so the JSON is complete,
///    but the summary/comparison only trusts read-side costs (and, for the
///    headline, SERVER_CERT_VERIFY specifically).
fn compute_durations_rustls(
    client_iters: &[Vec<RawCheckpoint>],
    server_iters: &[Vec<RawCheckpoint>],
) -> Vec<MeasurementRecord> {
    let mut records = Vec::new();

    for side_iters in [client_iters, server_iters] {
        for (idx, stream) in side_iters.iter().enumerate() {
            let iteration = idx as u64;
            let mut sorted: Vec<&RawCheckpoint> = stream.iter().collect();
            sorted.sort_by_key(|c| c.timestamp_ns);

            // Track the most recent RECORD_READ timestamp (the handler-local
            // baseline for the next processed message) and the previous
            // checkpoint (baseline for write deltas).
            let mut last_record_read: Option<u64> = None;
            let mut prev_ts: Option<u64> = None;

            for cp in &sorted {
                let name = cp.name.as_str();
                if name == "NEGOTIATE_START" {
                    prev_ts = Some(cp.timestamp_ns);
                    continue;
                }
                if name == "RECORD_READ" {
                    // Emit RECORD_READ as a measurement record. Its duration is
                    // the gap from the previous checkpoint — i.e. peer-wait time
                    // (how long this side was idle waiting for bytes).
                    if let Some(base) = prev_ts {
                        let duration_ns = cp.timestamp_ns.saturating_sub(base);
                        records.push(MeasurementRecord {
                            implementation: "rustls".to_string(),
                            handshake_type: "tls13_full".to_string(),
                            iteration,
                            message_name: cp.name.clone(),
                            role: cp.role.clone(),
                            direction: cp.direction.clone(),
                            duration_ns,
                            wall_ns: cp.wall_ns,
                        });
                    }
                    last_record_read = Some(cp.timestamp_ns);
                    prev_ts = Some(cp.timestamp_ns);
                    continue;
                }

                let baseline = if cp.direction == "read" {
                    // Read message: cost is from the preceding RECORD_READ, so
                    // peer-wait before the bytes arrived is excluded.
                    last_record_read.or(prev_ts)
                } else {
                    // Write message: delta from previous checkpoint (not a clean
                    // per-message cost; kept for coverage only).
                    prev_ts
                };

                if let Some(base) = baseline {
                    let duration_ns = cp.timestamp_ns.saturating_sub(base);
                    records.push(MeasurementRecord {
                        implementation: "rustls".to_string(),
                        handshake_type: "tls13_full".to_string(),
                        iteration,
                        message_name: cp.name.clone(),
                        role: cp.role.clone(),
                        direction: cp.direction.clone(),
                        duration_ns,
                        wall_ns: cp.wall_ns,
                    });
                }
                prev_ts = Some(cp.timestamp_ns);
            }
        }
    }
    records
}

// ============================================================================
// Helpers
// ============================================================================

fn get_cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn fmt_ns(ns: f64) -> String {
    if ns >= 1_000_000.0 {
        format!("{:.3} ms", ns / 1e6)
    } else if ns >= 1000.0 {
        format!("{:.3} us", ns / 1e3)
    } else {
        format!("{:.0} ns", ns)
    }
}

/// A no-op waker needed by s2n's async `poll_recv` (for reading session tickets).
fn noop_waker() -> std::task::Waker {
    use std::task::{RawWaker, RawWakerVTable, Waker};
    fn no_op(_: *const ()) {}
    fn clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}

pub struct InsecureAcceptAllCertificatesHandler {}
impl VerifyHostNameCallback for InsecureAcceptAllCertificatesHandler {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}

// ============================================================================
// Certificate generation
// ============================================================================

/// Certificate material in both PEM (for s2n-tls) and DER (for rustls) forms.
struct CertMaterial {
    // PEM forms for s2n-tls
    ca_pem: Vec<u8>,
    cert_chain_pem: Vec<u8>,
    key_pem: Vec<u8>,
    // Client cert (for mTLS)
    client_cert_chain_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
    // DER forms for rustls
    server_cert_der: Vec<u8>,
    ca_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
    client_cert_der: Vec<u8>,
    client_key_der: Vec<u8>,
}

/// Generate a CA certificate and a server certificate signed by it, using the
/// requested algorithm/key size. Returns both PEM (s2n-tls) and DER (rustls)
/// encodings so the same cert material drives both implementations.
fn generate_certs(sig_type: &str) -> CertMaterial {
    let alg: &'static SignatureAlgorithm = match sig_type {
        "rsa2048" | "rsa3072" | "rsa4096" => &PKCS_RSA_SHA256,
        "ecdsa256" => &PKCS_ECDSA_P256_SHA256,
        "ecdsa384" => &PKCS_ECDSA_P384_SHA384,
        _ => &PKCS_RSA_SHA256,
    };

    let rsa_key_size: Option<RsaKeySize> = match sig_type {
        "rsa2048" => Some(RsaKeySize::_2048),
        "rsa3072" => Some(RsaKeySize::_3072),
        "rsa4096" => Some(RsaKeySize::_4096),
        _ => None,
    };

    // Generate CA key pair
    let ca_key = if let Some(size) = rsa_key_size {
        KeyPair::generate_rsa_for(alg, size).expect("failed to generate CA RSA key")
    } else {
        KeyPair::generate_for(alg).expect("failed to generate CA key")
    };

    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Benchmark CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Generate server key pair
    let server_key = if let Some(size) = rsa_key_size {
        KeyPair::generate_rsa_for(alg, size).expect("failed to generate server RSA key")
    } else {
        KeyPair::generate_for(alg).expect("failed to generate server key")
    };

    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    // PEM chain: server cert + CA cert
    let cert_chain_pem = format!("{}{}", server_cert.pem(), ca_cert.pem());

    // Generate client cert + key (for mTLS), signed by the same CA.
    let client_key = if let Some(size) = rsa_key_size {
        KeyPair::generate_rsa_for(alg, size).expect("failed to generate client RSA key")
    } else {
        KeyPair::generate_for(alg).expect("failed to generate client key")
    };
    let mut client_params =
        CertificateParams::new(vec!["client.localhost".to_string()]).unwrap();
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "client.localhost");
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();
    let client_cert_chain_pem = format!("{}{}", client_cert.pem(), ca_cert.pem());

    CertMaterial {
        ca_pem: ca_cert.pem().into_bytes(),
        cert_chain_pem: cert_chain_pem.into_bytes(),
        key_pem: server_key.serialize_pem().into_bytes(),
        client_cert_chain_pem: client_cert_chain_pem.into_bytes(),
        client_key_pem: client_key.serialize_pem().into_bytes(),
        server_cert_der: server_cert.der().to_vec(),
        ca_cert_der: ca_cert.der().to_vec(),
        server_key_der: server_key.serialize_der(),
        client_cert_der: client_cert.der().to_vec(),
        client_key_der: client_key.serialize_der(),
    }
}

// ============================================================================
// Rustls timing driver
//
// rustls is inbound-only: each connection emits checkpoints for the messages
// it RECEIVES. We run a client and a server connection in-memory (no sockets),
// each with its own subscriber, then collect both streams. Per the handoff,
// rustls uses a per-connection relative epoch, so the two streams are kept
// separate and never merged onto one global timeline.
// ============================================================================

/// A rustls subscriber that records checkpoints into a shared buffer for one
/// connection (one handshake, one side).
struct RustlsRecorder {
    role: &'static str,
    buf: Arc<Mutex<Vec<RawCheckpoint>>>,
}

impl RustlsTimingSubscriber for RustlsRecorder {
    fn on_timing_checkpoint(&self, checkpoint: &RustlsCheckpoint) {
        let direction = match checkpoint.direction {
            RustlsDirection::Read => "read",
            RustlsDirection::Write => "write",
        };
        if let Ok(mut b) = self.buf.lock() {
            b.push(RawCheckpoint {
                name: checkpoint.name.clone(),
                role: self.role.to_string(),
                timestamp_ns: checkpoint.timestamp_ns,
                direction: direction.to_string(),
                wall_ns: wall_now(),
            });
        }
    }
}

/// Build rustls client and server configs from the generated cert material.
fn build_rustls_configs(
    certs: &CertMaterial,
    mtls: bool,
    no_pq: bool,
    resumed: bool,
) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    use rustls::crypto::aws_lc_rs;
    use rustls::server::WebPkiClientVerifier;

    let server_cert = CertificateDer::from(certs.server_cert_der.clone());
    let ca_cert = CertificateDer::from(certs.ca_cert_der.clone());
    let key = PrivateKeyDer::try_from(certs.server_key_der.clone())
        .expect("failed to parse server key DER");

    // Crypto provider restricted to AES-128-GCM-SHA256 (suite-matched with s2n).
    let mut provider = aws_lc_rs::default_provider();
    provider.cipher_suites = vec![aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    if no_pq {
        // Classical-only: restrict to X25519 (no ML-KEM hybrid).
        provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
    }
    let provider = Arc::new(provider);

    // Trust store (used by both server-verifies-client and client-verifies-server).
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.clone()).expect("failed to add CA to root store");

    // Server config.
    let server_config = if mtls {
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots.clone()))
            .build()
            .expect("client verifier build failed");
        rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("server protocol versions")
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server_cert.clone(), ca_cert.clone()], key)
            .expect("server config build failed")
    } else {
        rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("server protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![server_cert.clone(), ca_cert.clone()], key)
            .expect("server config build failed")
    };

    // Client config.
    let mut client_config = if mtls {
        let client_cert = CertificateDer::from(certs.client_cert_der.clone());
        let client_key = PrivateKeyDer::try_from(certs.client_key_der.clone())
            .expect("failed to parse client key DER");
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![client_cert, ca_cert], client_key)
            .expect("client auth cert failed")
    } else {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    client_config.resumption = if resumed {
        rustls::client::Resumption::in_memory_sessions(256)
    } else {
        rustls::client::Resumption::disabled()
    };

    (Arc::new(client_config), Arc::new(server_config))
}

/// Drive one in-memory rustls handshake, returning the client and server
/// checkpoint streams for this handshake.
fn run_rustls_handshake(
    client_config: &Arc<rustls::ClientConfig>,
    server_config: &Arc<rustls::ServerConfig>,
) -> (Vec<RawCheckpoint>, Vec<RawCheckpoint>) {
    let client_buf = Arc::new(Mutex::new(Vec::new()));
    let server_buf = Arc::new(Mutex::new(Vec::new()));

    // Each connection needs its own config carrying its own subscriber. Clone
    // the shared config and attach a fresh recorder.
    let mut cc = (**client_config).clone();
    cc.set_timing_subscriber(Arc::new(RustlsRecorder {
        role: "client",
        buf: client_buf.clone(),
    }));
    let mut sc = (**server_config).clone();
    sc.set_timing_subscriber(Arc::new(RustlsRecorder {
        role: "server",
        buf: server_buf.clone(),
    }));

    let server_name = ServerName::try_from("localhost").unwrap();
    let mut client =
        rustls::ClientConnection::new(Arc::new(cc), server_name).expect("client conn");
    let mut server = rustls::ServerConnection::new(Arc::new(sc)).expect("server conn");

    // In-memory cooperative handshake loop (no sockets).
    let mut buf = Vec::new();
    while client.is_handshaking() || server.is_handshaking() {
        // client -> server
        buf.clear();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        let mut cursor = &buf[..];
        while !cursor.is_empty() {
            let n = server.read_tls(&mut cursor).unwrap();
            if n == 0 {
                break;
            }
        }
        server.process_new_packets().unwrap();

        // server -> client
        buf.clear();
        while server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        let mut cursor = &buf[..];
        while !cursor.is_empty() {
            let n = client.read_tls(&mut cursor).unwrap();
            if n == 0 {
                break;
            }
        }
        client.process_new_packets().unwrap();
    }

    let c = client_buf.lock().unwrap().clone();
    let s = server_buf.lock().unwrap().clone();
    (c, s)
}

/// Build s2n-tls client and server configs from the cert material. The
/// `with_subscriber` flag controls whether the timing subscriber is attached
/// (off for the flamegraph hot loop, which wants minimal bookkeeping).
fn build_s2n_configs(
    certs: &CertMaterial,
    with_subscriber: bool,
    mtls: bool,
    no_pq: bool,
    resumed: bool,
) -> (s2n_tls::config::Config, s2n_tls::config::Config) {
    struct AcceptAll;
    impl s2n_tls::callbacks::VerifyHostNameCallback for AcceptAll {
        fn verify_host_name(&self, _hostname: &str) -> bool {
            true
        }
    }

    let server_config = {
        let mut builder = Builder::new();
        if no_pq {
            // Use a policy that only offers classical key exchange (no ML-KEM).
            builder
                .set_security_policy(&s2n_tls::security::DEFAULT_TLS13)
                .unwrap();
        } else {
            // TLS 1.3-only PQ policy with x25519 first in its ecc preferences,
            // so both hash-narrowing (needs min proto TLS1.3) and classical
            // key-share reuse (needs ecc_curves[0] == the hybrid's classical
            // curve) fire. Policies with secp256r1 first (e.g.
            // CloudFront-Upstream-*-PQ) disable reuse and add a P-256 keygen.
            builder
                .set_security_policy(
                    &s2n_tls::security::Policy::from_version("CloudFront-TLS-1-3-2025")
                        .unwrap(),
                )
                .unwrap();
        }
        builder
            .load_pem(&certs.cert_chain_pem, &certs.key_pem)
            .unwrap();
        if mtls {
            builder.trust_pem(&certs.ca_pem).unwrap();
            builder
                .set_client_auth_type(s2n_tls::enums::ClientAuthType::Required)
                .unwrap();
            builder.set_verify_host_callback(AcceptAll).unwrap();
        }
        if with_subscriber {
            builder.set_event_subscriber(TimingSubscriber).unwrap();
        }
        if resumed {
            builder.enable_session_tickets(true).unwrap();
            builder
                .add_session_ticket_key(
                    b"benchkey01",
                    b"a]secret/key/for/tickets!",
                    std::time::SystemTime::UNIX_EPOCH,
                )
                .unwrap();
        }
        builder.build().unwrap()
    };

    let client_config = {
        let mut builder = Builder::new();
        if no_pq {
            builder
                .set_security_policy(&s2n_tls::security::DEFAULT_TLS13)
                .unwrap();
        } else {
            // See the server-side comment: CloudFront-TLS-1-3-2025 keeps both
            // the hash-narrowing and classical key-share reuse optimizations active.
            builder
                .set_security_policy(
                    &s2n_tls::security::Policy::from_version("CloudFront-TLS-1-3-2025")
                        .unwrap(),
                )
                .unwrap();
        }
        builder.trust_pem(&certs.ca_pem).unwrap();
        builder.set_verify_host_callback(AcceptAll).unwrap();
        if mtls {
            builder
                .load_pem(&certs.client_cert_chain_pem, &certs.client_key_pem)
                .unwrap();
        }
        if resumed {
            let session_tickets = LIFOSessionResumption::default();
            builder.enable_session_tickets(true).unwrap();
            builder
                .set_session_ticket_callback(session_tickets.clone())
                .unwrap();
            builder
                .set_connection_initializer(session_tickets)
                .unwrap();
        }
        if with_subscriber {
            builder.set_event_subscriber(TimingSubscriber).unwrap();
        }
        builder.build().unwrap()
    };

    (client_config, server_config)
}

/// Run one s2n-tls in-memory handshake with no timing subscriber (used by the
/// flamegraph hot loop).
fn run_s2n_handshake_plain(
    client_config: &s2n_tls::config::Config,
    server_config: &s2n_tls::config::Config,
) {
    let mut pair = TestPair::from_configs(client_config, server_config);
    pair.client.set_server_name("localhost").unwrap();
    pair.handshake().expect("handshake failed");
}

/// Run one rustls in-memory handshake with no timing subscriber (used by the
/// flamegraph hot loop). Mirrors `run_rustls_handshake` minus the recorders.
fn run_rustls_handshake_plain(
    client_config: &Arc<rustls::ClientConfig>,
    server_config: &Arc<rustls::ServerConfig>,
) {
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut client =
        rustls::ClientConnection::new(client_config.clone(), server_name).expect("client conn");
    let mut server = rustls::ServerConnection::new(server_config.clone()).expect("server conn");

    let mut buf = Vec::new();
    while client.is_handshaking() || server.is_handshaking() {
        buf.clear();
        while client.wants_write() {
            client.write_tls(&mut buf).unwrap();
        }
        let mut cursor = &buf[..];
        while !cursor.is_empty() {
            let n = server.read_tls(&mut cursor).unwrap();
            if n == 0 {
                break;
            }
        }
        server.process_new_packets().unwrap();

        buf.clear();
        while server.wants_write() {
            server.write_tls(&mut buf).unwrap();
        }
        let mut cursor = &buf[..];
        while !cursor.is_empty() {
            let n = client.read_tls(&mut cursor).unwrap();
            if n == 0 {
                break;
            }
        }
        client.process_new_packets().unwrap();
    }
}

/// The flamegraph hot loop: run one implementation + one cert type in a tight
/// loop for a fixed wall-clock duration with minimal bookkeeping, so a `perf`
/// profile attributing samples to operations isn't polluted by JSON writing,
/// stats, or per-iteration printing.
fn run_hotloop(impl_name: &str, sig_type: &str, duration_secs: u64) {
    let certs = generate_certs(sig_type);
    let mtls = false; // hotloop always runs full (non-mTLS) for flamegraphs
    let no_pq = false; // hotloop always runs PQ (default) for flamegraphs
    let resumed = false; // hotloop always runs full (non-resumed) for flamegraphs
    let deadline = Instant::now() + std::time::Duration::from_secs(duration_secs);
    let mut count: u64 = 0;

    // Warm up briefly so the steady-state mean isn't polluted by cold-start
    // costs (modexp tables, allocator warmup).
    let warmup_n = 200;

    let loop_start;
    match impl_name {
        "s2n-tls" => {
            let (client_config, server_config) = build_s2n_configs(&certs, false, mtls, no_pq, resumed);
            for _ in 0..warmup_n {
                run_s2n_handshake_plain(&client_config, &server_config);
            }
            loop_start = Instant::now();
            while Instant::now() < deadline {
                for _ in 0..50 {
                    run_s2n_handshake_plain(&client_config, &server_config);
                }
                count += 50;
            }
        }
        "rustls" => {
            let (client_config, server_config) = build_rustls_configs(&certs, mtls, no_pq, resumed);
            for _ in 0..warmup_n {
                run_rustls_handshake_plain(&client_config, &server_config);
            }
            loop_start = Instant::now();
            while Instant::now() < deadline {
                for _ in 0..50 {
                    run_rustls_handshake_plain(&client_config, &server_config);
                }
                count += 50;
            }
        }
        other => {
            eprintln!("Unknown implementation: {other}. Use: s2n-tls|rustls");
            std::process::exit(1);
        }
    }

    let elapsed = loop_start.elapsed();
    let mean_us = elapsed.as_secs_f64() * 1e6 / count as f64;
    // Emit a machine-parseable line the analysis script can read for the
    // share -> absolute-time conversion (Option 1: share x hot-loop mean).
    eprintln!(
        "[hotloop] impl={impl_name} cert={sig_type} handshakes={count} \
         elapsed_s={:.3} mean_us={mean_us:.3}",
        elapsed.as_secs_f64()
    );
    // Also write the mean to a sidecar file so callers running this under perf
    // (e.g. make_version.sh) can read it back without scraping stderr.
    let sidecar = format!("hotloop_mean_{impl_name}_{sig_type}.txt");
    let _ = std::fs::write(&sidecar, format!("{mean_us:.3}"));
}

/// Check that perf + FlameGraph tools are on PATH; exit with guidance if not.
fn check_perf_tools() {
    use std::process::Command;
    for tool in ["perf", "stackcollapse-perf.pl", "flamegraph.pl"] {
        let found = Command::new("which")
            .arg(tool)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !found {
            eprintln!(
                "ERROR: required tool '{tool}' not found on PATH.\n\
                 Install perf, and clone https://github.com/brendangregg/FlameGraph\n\
                 then add it to PATH (provides stackcollapse-perf.pl and flamegraph.pl)."
            );
            std::process::exit(1);
        }
    }
}

/// Record one implementation under perf, render its SVG, fold its stacks, and
/// return (folded_stacks_path, hot_loop_mean_us).
fn record_and_fold(impl_name: &str, sig_type: &str, duration_secs: u64) -> (String, f64) {
    use std::process::Command;

    let self_exe = std::env::current_exe().expect("cannot find own executable path");
    let perf_data = format!("perf_{impl_name}_{sig_type}.data");
    let svg_out = format!("flamegraph_{impl_name}_{sig_type}.svg");
    let folded_out = format!("folded_{impl_name}_{sig_type}.txt");
    let sidecar = format!("hotloop_mean_{impl_name}_{sig_type}.txt");

    println!("Recording {impl_name} ({sig_type}) under perf for ~{duration_secs}s...");
    let status = Command::new("perf")
        .args(["record", "-F", "999", "-g", "--call-graph", "fp", "-o", &perf_data, "--"])
        .arg(&self_exe)
        .args(["--hotloop", impl_name, sig_type, &duration_secs.to_string()])
        .status()
        .expect("failed to launch perf record");
    if !status.success() {
        eprintln!("ERROR: perf record failed. Is kernel.perf_event_paranoid <= 1?");
        std::process::exit(1);
    }

    // perf script -> folded stacks file (input to flamegraph.pl).
    println!("Folding stacks -> {folded_out} ...");
    let perf_script = Command::new("perf")
        .args(["script", "-i", &perf_data])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to launch perf script");
    let folded_file = std::fs::File::create(&folded_out).expect("cannot create folded output");
    let collapse = Command::new("stackcollapse-perf.pl")
        .stdin(perf_script.stdout.unwrap())
        .stdout(folded_file)
        .status()
        .expect("failed to launch stackcollapse-perf.pl");
    if !collapse.success() {
        eprintln!("ERROR: stackcollapse-perf.pl failed.");
        std::process::exit(1);
    }

    // folded stacks -> SVG.
    println!("Rendering {svg_out} ...");
    let svg_file = std::fs::File::create(&svg_out).expect("cannot create SVG output");
    let flame = Command::new("flamegraph.pl")
        .arg("--title")
        .arg(format!("{impl_name} {sig_type} handshake"))
        .arg(&folded_out)
        .stdout(svg_file)
        .status()
        .expect("failed to launch flamegraph.pl");
    if !flame.success() {
        eprintln!("ERROR: flamegraph.pl failed.");
        std::process::exit(1);
    }

    // Read the hot-loop mean the subprocess wrote.
    let mean_us = std::fs::read_to_string(&sidecar)
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok())
        .unwrap_or(0.0);

    (folded_out, mean_us)
}

/// Driver for `--flamegraph`: record one implementation and render its SVG.
fn run_flamegraph(impl_name: &str, sig_type: &str) {
    check_perf_tools();
    let (folded, mean_us) = record_and_fold(impl_name, sig_type, 20);
    println!("Done: flamegraph_{impl_name}_{sig_type}.svg");
    println!("  folded stacks: {folded}");
    println!("  hot-loop mean: {mean_us:.1} us");
}

// ============================================================================
// Ground-truth crypto microbenchmark
//
// Per the methodology doc, the share->absolute-time conversion is validated by
// directly timing an isolated RSA-2048 sign and verify on the same core, using
// the same backend (aws-lc-rs) both libraries use. If `share x mean` says RSA
// sign ~= 280us and this isolated microbench agrees, the method is anchored to
// ground truth.
// ============================================================================

fn run_microbench(sig_type: &str) {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        KeyPair, RsaKeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256,
    };
    use std::time::Instant;

    if !sig_type.starts_with("rsa") {
        eprintln!(
            "microbench currently anchors RSA sign/verify only; got '{sig_type}'. \
             Use rsa2048|rsa3072|rsa4096."
        );
        std::process::exit(1);
    }

    // Generate a server key of the requested size via rcgen, hand the PKCS#8
    // DER to aws-lc-rs so we time the exact same primitive the handshake uses.
    let certs = generate_certs(sig_type);
    let key_pair = RsaKeyPair::from_pkcs8(&certs.server_key_der)
        .expect("failed to load RSA key into aws-lc-rs");

    let rng = SystemRandom::new();
    let msg = b"handshake transcript hash stand-in (32 bytes!!)";

    let iters = 5000u32;

    // Warm up.
    let mut sig = vec![0u8; key_pair.public_modulus_len()];
    for _ in 0..200 {
        key_pair
            .sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("sign failed");
    }

    // Time signing.
    let t0 = Instant::now();
    for _ in 0..iters {
        key_pair
            .sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("sign failed");
    }
    let sign_us = t0.elapsed().as_secs_f64() * 1e6 / iters as f64;

    // Time verifying (using the public key from the same pair).
    let public_key_der = key_pair.public_key().as_ref().to_vec();
    let public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key_der);
    for _ in 0..200 {
        public_key.verify(msg, &sig).expect("verify failed");
    }
    let t1 = Instant::now();
    for _ in 0..iters {
        public_key.verify(msg, &sig).expect("verify failed");
    }
    let verify_us = t1.elapsed().as_secs_f64() * 1e6 / iters as f64;

    println!("=== Crypto microbenchmark (ground-truth anchor) ===");
    println!("Backend: aws-lc-rs (same as both s2n-tls and rustls)");
    println!("Cert/key: {sig_type}, iterations: {iters}");
    println!("  RSA sign   (server private key): {sign_us:.2} us/op");
    println!("  RSA verify (client public key):  {verify_us:.2} us/op");
    println!(
        "\nCompare against the flamegraph estimate (share x hot-loop mean) and the\n\
         per-message SERVER_CERT_VERIFY_server measurement to validate the method."
    );
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Dispatch special modes first.
    //   --hotloop <impl> <cert> <secs>   (internal: run under perf)
    //   --flamegraph --impl <impl> <cert>  OR  --flamegraph <impl> <cert>
    if let Some(pos) = args.iter().position(|a| a == "--hotloop") {
        let impl_name = args.get(pos + 1).map(String::as_str).unwrap_or("s2n-tls");
        let sig_type = args.get(pos + 2).map(String::as_str).unwrap_or("rsa2048");
        let secs: u64 = args
            .get(pos + 3)
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);
        run_hotloop(impl_name, sig_type, secs);
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--microbench") {
        let sig_type = args.get(pos + 1).map(String::as_str).unwrap_or("rsa2048");
        run_microbench(sig_type);
        return;
    }
    // --dump-certs <cert_type> <dir>: write the generated PEMs to disk so
    // external workload generators (e.g. openssl_hotloop.c) can use the same
    // cert chain as the harness.
    if let Some(pos) = args.iter().position(|a| a == "--dump-certs") {
        let sig_type = args.get(pos + 1).map(String::as_str).unwrap_or("rsa2048");
        let dir = args.get(pos + 2).map(String::as_str).unwrap_or(".");
        let certs = generate_certs(sig_type);
        std::fs::create_dir_all(dir).expect("cannot create cert dump dir");
        for (name, bytes) in [
            ("chain.pem", &certs.cert_chain_pem),
            ("key.pem", &certs.key_pem),
            ("ca.pem", &certs.ca_pem),
        ] {
            let path = format!("{dir}/{sig_type}_{name}");
            std::fs::write(&path, bytes).expect("cannot write cert dump");
            println!("wrote {path}");
        }
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--flamegraph") {
        // Accept "--flamegraph --impl <impl> <cert>" or "--flamegraph <impl> <cert>".
        let rest: Vec<&str> = args[pos + 1..]
            .iter()
            .filter(|a| a.as_str() != "--impl")
            .map(String::as_str)
            .collect();
        let impl_name = rest.first().copied().unwrap_or("s2n-tls");
        let sig_type = rest.get(1).copied().unwrap_or("rsa2048");
        run_flamegraph(impl_name, sig_type);
        return;
    }

    let mtls = args.iter().any(|a| a == "--mtls");
    let no_pq = args.iter().any(|a| a == "--no-pq");
    let resumed = args.iter().any(|a| a == "--resumed");

    // Positional args (skip flags like --mtls, --no-pq).
    let positional: Vec<&str> = args[1..]
        .iter()
        .filter(|a| !a.starts_with("--"))
        .map(String::as_str)
        .collect();
    let sig_type = positional.first().copied().unwrap_or("rsa2048").to_string();
    let output_path = positional.get(1).copied().unwrap_or("results.json").to_string();

    match sig_type.as_str() {
        "rsa2048" | "rsa3072" | "rsa4096" | "ecdsa256" | "ecdsa384" => {}
        other => {
            eprintln!("Unknown: {other}. Use: rsa2048|rsa3072|rsa4096|ecdsa256|ecdsa384");
            std::process::exit(1);
        }
    };

    let warmup = 200u64;
    let measure = 1000u64;
    let handshake_type = if resumed {
        "tls13_resumed"
    } else if mtls {
        "tls13_mtls"
    } else {
        "tls13_full"
    };

    println!("TLS handshake timing ({handshake_type})");
    println!("============================================");
    println!("Cert: {sig_type}, Warmup: {warmup}, Measure: {measure}, mTLS: {mtls}");
    println!("Output: {output_path}");

    // Generate CA and server certs at runtime using rcgen (shared by both impls).
    let certs = generate_certs(&sig_type);

    let (client_config, server_config) = build_s2n_configs(&certs, true, mtls, no_pq, resumed);

    // ====================================================================
    // s2n-tls run
    // ====================================================================
    print!("[s2n-tls] Warming up...");
    for i in 0..warmup {
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.client.set_server_name("localhost").unwrap();
        if resumed {
            pair.client
                .set_waker(Some(&noop_waker()))
                .unwrap();
        }
        pair.handshake().expect("warmup handshake failed");
        if resumed {
            // Read the NewSessionTicket from the server so the
            // LIFOSessionResumption callback stores it for future connections.
            let _ = pair.client.poll_recv(&mut [0]);
        }
    }
    println!(" done.");
    CHECKPOINTS.lock().unwrap().clear();

    print!("[s2n-tls] Measuring...");
    let t0 = Instant::now();
    for _ in 0..measure {
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.client.set_server_name("localhost").unwrap();
        if resumed {
            pair.client.set_waker(Some(&noop_waker())).unwrap();
        }
        pair.handshake().expect("measurement handshake failed");
        if resumed {
            let _ = pair.client.poll_recv(&mut [0]);
        }
    }
    let s2n_elapsed = t0.elapsed();
    println!(" done.");

    let s2n_raw = CHECKPOINTS.lock().unwrap().clone();
    let mut measurements = compute_durations_s2n(&s2n_raw, measure);

    // ====================================================================
    // rustls run
    // ====================================================================
    let (rustls_client_cfg, rustls_server_cfg) = build_rustls_configs(&certs, mtls, no_pq, resumed);

    print!("[rustls] Warming up...");
    for _ in 0..warmup {
        let _ = run_rustls_handshake(&rustls_client_cfg, &rustls_server_cfg);
    }
    println!(" done.");

    print!("[rustls] Measuring...");
    let mut rustls_client_iters: Vec<Vec<RawCheckpoint>> = Vec::with_capacity(measure as usize);
    let mut rustls_server_iters: Vec<Vec<RawCheckpoint>> = Vec::with_capacity(measure as usize);
    let t1 = Instant::now();
    for _ in 0..measure {
        let (c, s) = run_rustls_handshake(&rustls_client_cfg, &rustls_server_cfg);
        rustls_client_iters.push(c);
        rustls_server_iters.push(s);
    }
    let rustls_elapsed = t1.elapsed();
    println!(" done.");

    let rustls_measurements =
        compute_durations_rustls(&rustls_client_iters, &rustls_server_iters);
    measurements.extend(rustls_measurements);

    let s2n_e2e_mean_us = s2n_elapsed.as_micros() as f64 / measure as f64;
    let rustls_e2e_mean_us = rustls_elapsed.as_micros() as f64 / measure as f64;

    // Group durations by (implementation, message_name, role) for stats so the
    // two implementations stay separate and role-matched (never name-only).
    let mut grouped: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for r in &measurements {
        let key = format!(
            "{}|{}_{}_{}",
            r.implementation, r.message_name, r.role, r.direction
        );
        grouped.entry(key).or_default().push(r.duration_ns);
    }

    let reproducibility: BTreeMap<String, MessageStats> = grouped
        .iter()
        .map(|(key, samples)| {
            let n = samples.len() as f64;
            let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / n;
            let var: f64 = samples
                .iter()
                .map(|&x| (x as f64 - mean).powi(2))
                .sum::<f64>()
                / n;
            let stddev = var.sqrt();
            let cv = if mean > 0.0 {
                stddev / mean * 100.0
            } else {
                0.0
            };
            (
                key.clone(),
                MessageStats {
                    mean_ns: mean,
                    stddev_ns: stddev,
                    cv_percent: cv,
                },
            )
        })
        .collect();

    let output = OutputFile {
        metadata: Metadata {
            cpu_model: get_cpu_model(),
            warmup_iterations: warmup,
            measurement_iterations: measure,
            cert_type: sig_type.clone(),
            s2n_mean_us: s2n_e2e_mean_us,
            rustls_mean_us: rustls_e2e_mean_us,
        },
        measurements,
        reproducibility: reproducibility.clone(),
    };

    // Write JSON
    let file = std::fs::File::create(&output_path).unwrap_or_else(|e| {
        eprintln!("ERROR: Cannot create {output_path}: {e}");
        std::process::exit(1);
    });
    if let Err(e) = serde_json::to_writer_pretty(file, &output) {
        eprintln!("ERROR: JSON serialization failed: {e}");
        std::process::exit(1);
    }

    // Print per-implementation summary tables.
    println!("\n=== End-to-end ===");
    println!("  s2n-tls mean = {s2n_e2e_mean_us:.1} us per handshake");
    println!("  rustls  mean = {rustls_e2e_mean_us:.1} us per handshake");

    for (impl_name, e2e_mean_us) in [
        ("s2n-tls", s2n_e2e_mean_us),
        ("rustls", rustls_e2e_mean_us),
    ] {
        println!("\n--- {impl_name} (per-message cost; dir = read/write) ---");
        println!(
            "{:<26}  {:<7}  {:<6}  {:>12}  {:>10}  {:>13}",
            "Message", "Role", "Dir", "Mean", "Median", "% of Hs"
        );
        println!(
            "{:<26}  {:<7}  {:<6}  {:>12}  {:>10}  {:>13}",
            "-------", "----", "---", "----", "------", "-------"
        );

        for msg in HANDSHAKE_ORDER {
            for role in &["server", "client"] {
                for dir in &["read", "write"] {
                    let key = format!("{}|{}_{}_{}", impl_name, msg, role, dir);
                    if let Some(stats) = reproducibility.get(&key) {
                        let samples = &grouped[&key];
                        let mut sorted = samples.clone();
                        sorted.sort();
                        let median = sorted[sorted.len() / 2];
                        let pct = (stats.mean_ns / (e2e_mean_us * 1000.0)) * 100.0;
                        let pct_str = format!("{:.1}%", pct);
                        println!(
                            "{:<26}  {:<7}  {:<6}  {:>12}  {:>10}  {:>13}",
                            msg,
                            role,
                            dir,
                            fmt_ns(stats.mean_ns),
                            fmt_ns(median as f64),
                            pct_str
                        );
                    }
                }
            }
        }
    }
}
