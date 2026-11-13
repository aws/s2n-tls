// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wire format stability of client sessions (which hold the server's session
//! ticket) and serialized connections.
//!
//! The fixtures in `fixtures/` are produced with randomness and the clock pinned, so
//! the same code always produces the same bytes. Two tests use them:
//!
//! - `current_version_reads_all_fixtures` (backwards compatibility): the current
//!   version can resume from every checked-in client session and continue every
//!   checked-in serialized connection. This is how a newer version is shown to read
//!   what an older version wrote.
//! - `current_version_writes_checked_in_fixtures` (forwards compatibility): the
//!   current version produces exactly the bytes that are checked in. This is
//!   deliberately strict. Anything that changes these bytes (a wire format change, but
//!   also a change in how much randomness the handshake draws, or in the handshake
//!   transcript) fails it, so that every such change is looked at on purpose.
//!
//! If the second test fails on a change that is meant to alter the wire format,
//! regenerate with `UPDATE_FIXTURES=1 cargo test --test wire_format`.
//!
//! Fixtures are flat files named `tls12_<artifact>.bin` and `tls13_<artifact>.bin`.
//!
//! Run with `cargo test --no-default-features --features pq --test wire_format`.

// The deterministic randomness only reaches the aws-lc that the bindings build, and
// the exact bytes depend on that libcrypto. Like the memory test, this is a "sensitive"
// test: it is skipped by default and runs with `--no-default-features`.
#![cfg(not(feature = "no-sensitive-tests"))]

use s2n_tls::{
    callbacks::WallClock,
    enums::{SerializationVersion, Version},
    security::Policy,
};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use tls_harness::{
    cohort::{
        s2n_tls::{SessionTicketStorage, KEY_NAME, KEY_VALUE},
        S2NConfig, S2NConnection,
    },
    harness::TlsConfigBuilder,
    Mode, SigType, TlsConnPair,
};

const CLIENT_SESSION: &str = "client_session";
const CLIENT_CONNECTION: &str = "client_connection";
const SERVER_CONNECTION: &str = "server_connection";

/// 2026-11-12T00:00:00Z. Tickets expire, so the clock is pinned for fixtures.
const FIXTURE_TIME: Duration = Duration::from_secs(1_794_441_600);

struct FixedClock;

impl WallClock for FixedClock {
    fn get_time_since_epoch(&self) -> Duration {
        FIXTURE_TIME
    }
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/wire_format/fixtures")
}

fn fixture_path(version: Version, artifact: &str) -> PathBuf {
    let prefix = match version {
        Version::TLS12 => "tls12",
        Version::TLS13 => "tls13",
        _ => panic!("no fixtures for {version:?}"),
    };
    fixtures_dir().join(format!("{prefix}_{artifact}.bin"))
}

const CURRENT_VERSIONS: [Version; 2] = [Version::TLS12, Version::TLS13];

fn client_config(policy: &str) -> (SessionTicketStorage, S2NConfig) {
    let storage = SessionTicketStorage::default();
    let mut config = s2n_tls::config::Builder::new_test_config(Mode::Client);
    config
        .set_security_policy(&Policy::from_version(policy).unwrap())
        .unwrap()
        .set_wall_clock(FixedClock)
        .unwrap()
        .set_serialization_version(SerializationVersion::V1)
        .unwrap()
        .enable_session_tickets(true)
        .unwrap()
        .set_session_ticket_callback(storage.clone())
        .unwrap();
    config.set_trust(SigType::Rsa2048);
    (storage, config.build().unwrap().into())
}

fn server_config() -> S2NConfig {
    let mut config = s2n_tls::config::Builder::new_test_config(Mode::Server);
    config
        .set_security_policy(&Policy::from_version("20190801").unwrap())
        .unwrap()
        .set_wall_clock(FixedClock)
        .unwrap()
        .set_serialization_version(SerializationVersion::V1)
        .unwrap()
        .enable_session_tickets(true)
        .unwrap()
        // An intro time of 0 means "now", which is the fixed clock.
        .add_session_ticket_key(KEY_NAME.as_bytes(), &KEY_VALUE, SystemTime::UNIX_EPOCH)
        .unwrap();
    config.set_chain(SigType::Rsa2048);
    config.build().unwrap().into()
}

type Pair = TlsConnPair<S2NConnection, S2NConnection>;

fn serialize(conn: &S2NConnection) -> Vec<u8> {
    let connection = conn.connection();
    let mut bytes = vec![0; connection.serialization_length().unwrap()];
    connection.serialize(&mut bytes).unwrap();
    bytes
}

/// The three serialized artifacts of a handshake: the client's session, and both
/// peers of the connection.
#[derive(Debug, PartialEq)]
struct VersionedSerializedArtifacts {
    version: Version,
    client_session: Vec<u8>,
    client_connection: Vec<u8>,
    server_connection: Vec<u8>,
}

impl VersionedSerializedArtifacts {
    /// The security policy is how the client is limited to a protocol version. 20170210
    /// has no TLS1.3 cipher suites, while 20190801 supports TLS1.0 to TLS1.3.
    fn client_policy(&self) -> &'static str {
        match self.version {
            Version::TLS12 => "20170210",
            Version::TLS13 => "20190801",
            version => panic!("no client policy for {version:?}"),
        }
    }

    fn from_disk(version: Version) -> Self {
        let read = |artifact| std::fs::read(fixture_path(version, artifact)).unwrap();
        Self {
            version,
            client_session: read(CLIENT_SESSION),
            client_connection: read(CLIENT_CONNECTION),
            server_connection: read(SERVER_CONNECTION),
        }
    }

    fn from_current_revision(version: Version) -> Self {
        let mut artifacts = Self {
            version,
            client_session: Vec::new(),
            client_connection: Vec::new(),
            server_connection: Vec::new(),
        };
        let (ticket_storage, client_config) = client_config(artifacts.client_policy());
        let server_config = server_config();

        det_rand::reset();
        let mut pair: Pair = TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();
        // TLS1.3 tickets arrive after the handshake.
        pair.round_trip_assert(10_000).unwrap();

        artifacts.client_session = ticket_storage.get_ticket();
        artifacts.client_connection = serialize(&pair.client);
        artifacts.server_connection = serialize(&pair.server);
        artifacts
    }

    fn files(&self) -> [(&'static str, &[u8]); 3] {
        [
            (CLIENT_SESSION, &self.client_session),
            (CLIENT_CONNECTION, &self.client_connection),
            (SERVER_CONNECTION, &self.server_connection),
        ]
    }

    fn write(&self) {
        std::fs::create_dir_all(fixtures_dir()).unwrap();
        for (artifact, bytes) in self.files() {
            std::fs::write(fixture_path(self.version, artifact), bytes).unwrap();
        }
    }

    /// Checks that the current code can resume from the client session and continue
    /// both peers of the serialized connection.
    fn assert_readable(&self) {
        let version = self.version;
        let (_, client_config) = client_config(self.client_policy());
        let server_config = server_config();

        // the ticket should be resumable
        {
            let mut pair: Pair = TlsConnPair::from_configs(&client_config, &server_config);
            pair.client
                .connection_mut()
                .set_session_ticket(&self.client_session)
                .unwrap();
            pair.handshake().unwrap();
            pair.round_trip_assert(10_000).unwrap();
            assert!(pair.client.connection().resumed(), "{version:?}: client");
            assert!(pair.server.connection().resumed(), "{version:?}: server");
        }

        // deserialized connections should be able to read & write
        {
            let mut pair: Pair = TlsConnPair::from_configs(&client_config, &server_config);
            pair.client
                .connection_mut()
                .deserialize(&self.client_connection)
                .unwrap();
            pair.server
                .connection_mut()
                .deserialize(&self.server_connection)
                .unwrap();
            pair.round_trip_assert(10_000).unwrap();
        }
    }
}

/// The tests confirms that the current version of s2n-tls produces the exact same
/// artifacts as it previously did. This helps confirm that old & new versions of
/// s2n-tls will still be able to talk with each other.
///
/// If we are deliberately publishing a non-compatible version (for session tickets)
/// then we should re-generate the artifacts.
///
/// Note that this test is overly sensitive: any change in s2n-tls wire bytes will
/// cause the resumption artifact to differ (because it incorporates the transcript hash).
/// In this case the artifact can simply be re-generated.
///
/// There should NEVER by an incompatible version bump for connection serialization.
/// In the event that you add a new serialized connection version, expand this test
/// to ensure that we continue to support V1.
#[test]
fn current_version_writes_checked_in_fixtures() {
    for version in CURRENT_VERSIONS {
        let actual = VersionedSerializedArtifacts::from_current_revision(version);
        assert_eq!(
            actual,
            VersionedSerializedArtifacts::from_current_revision(version)
        );

        // uncomment to update artifacts
        // actual.write()
        assert_eq!(
            VersionedSerializedArtifacts::from_disk(version),
            actual,
            "Either s2n-tls wire behavior changed, or serialization format changed"
        );
    }
}

#[test]
fn current_version_reads_all_fixtures() {
    for version in CURRENT_VERSIONS {
        VersionedSerializedArtifacts::from_disk(version).assert_readable();
    }
}

mod det_rand {
    //! Deterministic AWS-LC randomness, without patching aws-lc-sys.
    //!
    //! By default, AWS-LC makes it very hard to get deterministic randomness because
    //! CPU jitter/prediction resistance will randomly shove in new entropy after a
    //! fixed number of calls.
    //!
    //! So we use `override_entropy_source_method_FOR_TESTING` to disable all of that
    //! and get completely deterministic `RAND_bytes` output.
    //!
    //! The override is process-global, so we only do this in `tests/*` to keep it in
    //! it's own binary.

    use aws_lc_sys::AWSLC_thread_local_clear;
    use core::ffi::c_void;
    use std::sync::Once;

    /// `CTR_DRBG_ENTROPY_LEN`
    const SEED_LEN: usize = 48;

    /// Mirror of `struct entropy_source_methods` in aws-lc
    /// `crypto/fipsmodule/rand/entropy/internal.h`. `Option<fn>` is a nullable pointer.
    #[repr(C)]
    struct EntropySourceMethods {
        initialize: unsafe extern "C" fn(*mut c_void) -> i32,
        zeroize_thread: unsafe extern "C" fn(*mut c_void),
        free_thread: unsafe extern "C" fn(*mut c_void),
        get_seed: unsafe extern "C" fn(*const c_void, *mut u8) -> i32,
        get_extra_entropy: Option<unsafe extern "C" fn(*const c_void, *mut u8) -> i32>,
        get_prediction_resistance: Option<unsafe extern "C" fn(*const c_void, *mut u8) -> i32>,
        id: i32,
    }

    // SAFETY: only function pointers and an integer.
    unsafe impl Sync for EntropySourceMethods {}

    extern "C" {
        #[link_name = "aws_lc_0_47_0_override_entropy_source_method_FOR_TESTING"]
        fn override_entropy_source_method_for_testing(methods: *const EntropySourceMethods);
    }

    unsafe extern "C" fn initialize(_: *mut c_void) -> i32 {
        1
    }

    unsafe extern "C" fn noop(_: *mut c_void) {}

    unsafe extern "C" fn get_seed(_: *const c_void, out: *mut u8) -> i32 {
        core::ptr::write_bytes(out, 0, SEED_LEN);
        1
    }

    static DETERMINISTIC_SOURCE: EntropySourceMethods = EntropySourceMethods {
        initialize,
        zeroize_thread: noop,
        free_thread: noop,
        get_seed,
        get_extra_entropy: None,
        get_prediction_resistance: None,
        id: 0,
    };

    /// Resets the calling thread's AWS-LC randomness to a fixed state. Afterwards
    /// `RAND_bytes` on this thread returns the same sequence every time.
    pub fn reset() {
        static INSTALL: Once = Once::new();
        // SAFETY: `DETERMINISTIC_SOURCE` is a static that matches the C struct layout.
        INSTALL.call_once(|| unsafe {
            override_entropy_source_method_for_testing(&DETERMINISTIC_SOURCE)
        });
        // SAFETY: only drops AWS-LC thread-locals of this thread.
        assert_eq!(unsafe { AWSLC_thread_local_clear() }, 1);
    }
}
