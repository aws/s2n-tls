//! This module includes the logic for runtime determination of "capabilities".
//!
//! There are two design choices that this module makes
//! 1. integration tests should express their requirements in capabilities, not libcryptos.
//!    E.g. "I need TLS 1.3", not "I don't run with OpenSSL 1.0.2"
//! 2. The source of truth for supported capabilities is the library behavior,
//!    not a collection of environment variables.
//!
//! To support 1, a test can assert on the required [`Capability`].
//! To support 2, we use runtime "feature probes" to check what is supported, and
//! only look at the special `S2N_LIBCRYPTO` env variable, not as a source of truth.

use openssl::ssl::SslContextBuilder;
use s2n_tls::security::Policy;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        LazyLock,
    },
    time::Duration,
};
use strum::IntoEnumIterator;
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair,
};

/// The maximum amount of time that the "should skip" tests will take. If this
/// runtime is exceeded the "total_test_assertion" test will panic.
const MAX_EXPECTED_TEST_TIME: Duration = Duration::from_secs(1);

/// The total number of times that [`Capability::should_skip`] was expected to be
/// called.
///
/// This needs to be updated when new tests are added.
const EXPECTED_TOTAL_TESTS: u64 = 5;

/// That total number of times that [`Capability::should_skip`] was called
static TOTAL_TESTS: AtomicU64 = AtomicU64::new(0);

/// That total number of times that [`Capability::should_skip`] returned true
static TOTAL_SKIPPED: AtomicU64 = AtomicU64::new(0);

/// A `Capability` represents a functionality of s2n-tls that may or may not be
/// available depending on the linked libcrypto.
///
/// The only public interface for interacting with Capabilities is [`Capability::should_skip`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum Capability {
    /// Support for TLS 1.3
    Tls13,
    /// Support for ML-DSA and ML-KEM
    PQAlgorithms,
}

impl Capability {
    /// This will return `true` if any of the required capabilities are not available.
    ///
    /// Prefer to use [`required_capability_or_skip`], which will add a helpful file/line
    /// number when a skip occurs.
    ///
    /// Internally, this will keep track of the total number of calls as well as
    /// the number of "skips".
    pub fn should_skip(required_capabilities: &[Capability]) -> bool {
        let all_supported = required_capabilities
            .iter()
            .all(|capability| capability.supported());
        if !all_supported {
            TOTAL_SKIPPED.fetch_add(1, Ordering::SeqCst);
        }
        TOTAL_TESTS.fetch_add(1, Ordering::SeqCst);

        if TOTAL_TESTS.load(Ordering::SeqCst) > EXPECTED_TOTAL_TESTS {
            panic!(
                "Too many tests. You should update `EXPECTED_TOTAL_TESTS` in `capability_check.rs`"
            );
        }

        !all_supported
    }

    /// a cheap, cached check if a capability is supported
    fn supported(&self) -> bool {
        static CAPABILITY_SUPPORT_CACHE: LazyLock<HashMap<Capability, bool>> =
            LazyLock::new(|| {
                Capability::iter()
                    .map(|capability| (capability, capability.runtime_check()))
                    .collect()
            });

        *CAPABILITY_SUPPORT_CACHE.get(self).unwrap()
    }

    /// an expensive, non-cached check if a capability is supported
    fn runtime_check(&self) -> bool {
        match self {
            Capability::Tls13 => Capability::tls13_check(),
            Capability::PQAlgorithms => Capability::pq_check(),
        }
    }

    fn tls13_check() -> bool {
        // supports TLS 1.0 -> TLS 1.3
        let security_policy = Policy::from_version("20190801").unwrap();
        let mut pair: TlsConnPair<S2NConnection, S2NConnection> = {
            let mut configs = TlsConfigBuilderPair::<
                s2n_tls::config::Builder,
                s2n_tls::config::Builder,
            >::default();
            configs
                .client
                .set_security_policy(&security_policy)
                .unwrap();
            configs
                .server
                .set_security_policy(&security_policy)
                .unwrap();
            configs.connection_pair()
        };
        pair.handshake().unwrap();
        pair.negotiated_tls13()
    }

    fn pq_check() -> bool {
        // TLS 1.3 is a pre-req for PQ.
        if !Capability::tls13_check() {
            return false;
        }

        let ml_kem = {
            let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
                let mut configs =
                    TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
                // configure the client to only support ML-KEM
                configs
                    .client
                    .set_groups_list("SecP384r1MLKEM1024")
                    .unwrap();
                configs
                    .server
                    .set_security_policy(&Policy::from_version("default_pq").unwrap())
                    .unwrap();
                configs.connection_pair()
            };

            let handshake_result = pair.handshake();
            match handshake_result {
                Ok(_) => {
                    let group = pair.server.connection().selected_key_exchange_group();
                    assert_eq!(group, Some("SecP384r1MLKEM1024"));
                    true
                }
                Err(e) => {
                    // S2N_ERR_ECDHE_UNSUPPORTED_CURVE
                    assert_eq!(
                        e.to_string(),
                        "Unsupported EC curve was presented during an ECDHE handshake"
                    );
                    false
                }
            }
        };

        let ml_dsa = {
            const TEST_PEMS_PATH: &str =
                concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../tests/pems/mldsa/");
            let cert_path = PathBuf::from(TEST_PEMS_PATH).join("ML-DSA-87.crt");
            let key_path = PathBuf::from(TEST_PEMS_PATH).join("ML-DSA-87-seed.priv");

            let mut config = s2n_tls::config::Builder::new();
            let dsa_load = config.load_pem(
                &std::fs::read(cert_path).unwrap(),
                &std::fs::read(key_path).unwrap(),
            );
            match dsa_load {
                Ok(_) => true,
                Err(e) => {
                    if e.name() == "S2N_ERR_DECODE_PRIVATE_KEY" {
                        false
                    } else {
                        panic!("unexpected error {:?}", e);
                    }
                }
            }
        };

        // sanity check: As of 2025-08-21 these should always be equal, although
        // that may change in the future
        assert_eq!(ml_kem, ml_dsa);
        ml_kem && ml_dsa
    }
}

/// Describe the required capabilities to run a test.
///
/// If these are are not satisfied, `return`, passing the test.
#[macro_export]
macro_rules! required_capability_or_skip {
    ( $( $x:expr ),* ) => {
        {
            let mut required_capabilities = Vec::new();
            $(
                required_capabilities.push($x);
            )*
            let should_skip = crate::capability_check::Capability::should_skip(&required_capabilities);
            if should_skip {
                println!("skipping {}:{}", std::file!(), std::line!());
                return;
            }
        }
    };
}

/// Describe the required capabilities to run a test.
///
/// If these are are not satisfied, `return Ok(())`, passing the test.
#[macro_export]
macro_rules! required_capability_or_skip_ok {
    ( $( $x:expr ),* ) => {
        {
            let mut required_capabilities = Vec::new();
            $(
                required_capabilities.push($x);
            )*
            let should_skip = crate::capability_check::Capability::should_skip(&required_capabilities);
            if should_skip {
                println!("skipping {}:{}", std::file!(), std::line!());
                return Ok(());
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_check::{Capability, EXPECTED_TOTAL_TESTS, TOTAL_TESTS};
    use std::{
        sync::atomic::Ordering,
        time::{Duration, Instant},
    };

    /// Retrieve the libcrypto from the `S2N_LIBCRYPTO` env var if available, otherwise
    /// return "awslc".
    ///
    /// S2N_LIBCRYPTO is set in CI as well as the Nix devshell.
    fn get_libcrypto() -> String {
        if let Ok(libcrypto) = std::env::var("S2N_LIBCRYPTO") {
            return libcrypto;
        } else {
            return "awslc".to_string();
        }
    }

    /// Assert that we only skip the expected number of tests.
    #[test]
    fn skipped_tests() {
        // we use a very lazy spin lock instead of a condvar because it's simpler
        // and we aren't worried about efficiency
        let start = Instant::now();

        while TOTAL_TESTS.load(Ordering::SeqCst) < EXPECTED_TOTAL_TESTS {
            std::thread::sleep(Duration::from_millis(1));
            if start.elapsed() > MAX_EXPECTED_TEST_TIME {
                println!("Expected to see {EXPECTED_TOTAL_TESTS} tests in {MAX_EXPECTED_TEST_TIME:?}, but only saw {}", TOTAL_TESTS.load(Ordering::SeqCst));
                println!("If you removed tests please update `EXPECTED_TOTAL_TESTS`.");
                println!("If you added tests that take longer than {MAX_EXPECTED_TEST_TIME:?}");
                println!("please consider making them faster rather than updating MAX_EXPECTED_TEST_TIME");
                panic!("too slow");
            }
        }

        let skips = TOTAL_SKIPPED.load(Ordering::SeqCst);
        println!("libcrypto is {}", get_libcrypto());
        let expected_skips = match get_libcrypto().as_str() {
            "awslc" => 0,
            "openssl-3.0" | "openssl-1.1.1" => 4,
            "openssl-1.0.2" => 5,
            unrecognized => panic!("unrecognized libcrypto: {unrecognized}"),
        };
        assert_eq!(skips, expected_skips);
    }

    /// Assert that we are correctly detecting s2n-tls capabilities
    #[test]
    fn supported_capabilities() {
        let libcrypto = get_libcrypto();
        let libcrypto = libcrypto.as_str();

        // PQ is only supported with AWS-LC
        let pq_expected = libcrypto == "awslc";
        assert_eq!(Capability::PQAlgorithms.supported(), pq_expected);

        // openssl 1.0.2 doesn't support RSA-PSS, so TLS 1.3 is unsupported
        let tls13_supported = libcrypto != "openssl-1.0.2";
        assert_eq!(Capability::Tls13.supported(), tls13_supported);
    }
}
