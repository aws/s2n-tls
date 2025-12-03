//! These integration tests look at our group negotiation logic.
//!
//! s2n-tls has some non-standard negotiation behaviors, and will prefer to negotiate
//! PQ where possible (even at the cost of an RTT) and also has a "strongly preferred
//! groups" feature that serves as a "hammer" to force clients to negotiate a particular
//! group whenever possible.

use std::sync::LazyLock;

use brass_aphid_wire_decryption::decryption::key_manager::KeyManager;
use brass_aphid_wire_messages::iana;
use openssl::ssl::SslContextBuilder;
use s2n_tls::security::Policy;
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair,
};

struct Trial {
    client_group_configuration: String,
    server_policy: &'static Policy,
}

impl Trial {
    /// Indicate the groups to set on the openssl client, e.g. "SecP384r1MLKEM1024"
    fn new(client_groups: String, server_policy: &'static Policy) -> Self {
        Self {
            client_group_configuration: client_groups,
            server_policy,
        }
    }
}

#[derive(Debug)]
struct Outcome {
    /// The key shares from the first client hello
    client_key_shares: Vec<iana::Group>,
    /// The supported groups in the first client hello
    client_supported_groups: Vec<iana::Group>,
    server_selected_group: iana::Group,
    hello_retry_request: bool,
}

/// KEMS -> [X25519MLKEM768, Secp256r1MLKEM768, Secp384r1MLKEM1024]
/// ECC -> [secp256r1, x25519, secp384r1, secp521r1]
static PQ_ENABLED_POLICY: LazyLock<s2n_tls::security::Policy> =
    LazyLock::new(|| Policy::from_version("20251014").unwrap());

/// strongly preferred groups -> []
/// ECC -> []
static STRONGLY_PREFERRED_GROUPS: LazyLock<s2n_tls::security::Policy> =
    LazyLock::new(|| Policy::from_version("20251014").unwrap());

impl Trial {
    fn handshake(&self) -> Outcome {
        let key_manager = KeyManager::new();
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs
                .server
                .set_security_policy(self.server_policy)
                .unwrap();
            key_manager.enable_s2n_logging(&mut configs.server);
            configs
                .client
                .set_groups_list(&self.client_group_configuration)
                .unwrap();
            configs.connection_pair()
        };
        pair.io.enable_recording();
        pair.io.enable_decryption(key_manager.clone());

        pair.handshake().unwrap();
        pair.shutdown().unwrap();

        let mut transcript = pair.io.decrypter.lock().unwrap();
        let transcript = transcript.as_mut().unwrap().transcript();
        let ch = transcript.client_hellos().first().unwrap().clone();
        let key_shares = ch.key_share().unwrap();
        let supported_groups = ch.supported_groups().unwrap();

        let sh = transcript.server_hello();
        Outcome {
            client_key_shares: key_shares,
            client_supported_groups: supported_groups,
            server_selected_group: sh.selected_group().unwrap().unwrap(),
            hello_retry_request: transcript.hello_retry_request().is_some(),
        }
    }
}

/// Classical Key Share Preference:
///
/// When s2n-tls receives a key share from the client AND that group is allowed
/// by the security policy, it will choose that group even if it isn't the highest
/// server preference.
///
/// As long as the client key share is supported (but not necessarily preferred)
/// by the server then it will be selected, and there will be no HRR.
#[test]
fn classical_group_selection() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let trial = Trial::new(
        "secp256r1:secp384r1:secp521r1".to_owned(),
        &PQ_ENABLED_POLICY,
    );
    let outcome = trial.handshake();
    assert_eq!(outcome.client_key_shares, vec![iana::constants::secp256r1]);
    assert_eq!(outcome.server_selected_group, iana::constants::secp256r1);
    assert!(!outcome.hello_retry_request);

    let trial = Trial::new(
        "secp384r1:secp521r1:secp256r1".to_owned(),
        &PQ_ENABLED_POLICY,
    );
    let outcome = trial.handshake();
    assert_eq!(outcome.client_key_shares, vec![iana::constants::secp384r1]);
    assert_eq!(outcome.server_selected_group, iana::constants::secp384r1);
    assert!(!outcome.hello_retry_request);

    let trial = Trial::new(
        "secp521r1:secp256r1:secp384r1".to_owned(),
        &PQ_ENABLED_POLICY,
    );
    let outcome = trial.handshake();
    assert_eq!(outcome.client_key_shares, vec![iana::constants::secp521r1]);
    assert_eq!(outcome.server_selected_group, iana::constants::secp521r1);
    assert!(!outcome.hello_retry_request);
}

/// PQ Key Share Preference:
///
/// When s2n-tls receives a key share from the client AND that group is allowed
/// by the security policy, it will choose that group even if it isn't the highest
/// server preference.
#[test]
fn pq_group_selection() {
    let trial = Trial::new("secp384r1:X25519MLKEM768".to_owned(), &PQ_ENABLED_POLICY);
    let outcome = trial.handshake();
    assert_eq!(outcome.client_key_shares, vec![iana::constants::secp384r1]);
    assert_eq!(
        outcome.server_selected_group,
        iana::constants::X25519MLKEM768
    );
    assert!(outcome.hello_retry_request);
}

/// Strongly Preferred Groups:
///
/// If the server's strongly preferred group is in the clients supported groups,
/// then negotiated of the group will be forced, even at the cost of an HRR.
///
/// Otherwise normal group negotiation logic applies
#[test]
fn strongly_preferred_groups() {
    // happy path: strongly preferred group is client key share
    let trial = Trial::new("secp384r1:secp256r1".to_owned(), &STRONGLY_PREFERRED_GROUPS);
    let outcome = trial.handshake();
    assert_eq!(outcome.client_key_shares, vec![iana::constants::secp384r1]);
    assert_eq!(outcome.server_selected_group, iana::constants::secp384r1);
    assert!(!outcome.hello_retry_request);

    // forced negotiation of strongly preferred group
    let trial = Trial::new("secp256r1:secp384r1".to_owned(), &STRONGLY_PREFERRED_GROUPS);
    let outcome = trial.handshake();
    assert_eq!(outcome.client_key_shares, vec![iana::constants::secp256r1]);
    assert_eq!(outcome.server_selected_group, iana::constants::secp384r1);
    assert!(outcome.hello_retry_request);

    // client doesn't support strongly preferred group: 1RTT negotiation
    let trial = Trial::new("secp256r1:x448".to_owned(), &STRONGLY_PREFERRED_GROUPS);
    let outcome = trial.handshake();
    assert_eq!(outcome.client_key_shares, vec![iana::constants::secp256r1]);
    assert_eq!(outcome.server_selected_group, iana::constants::secp256r1);
    assert!(!outcome.hello_retry_request);

    // client doesn't support strongly preferred group: HRR negotiation
    let trial = Trial::new("x448:secp256r1".to_owned(), &STRONGLY_PREFERRED_GROUPS);
    let outcome = trial.handshake();
    assert_eq!(outcome.client_key_shares, vec![iana::constants::x448]);
    assert_eq!(outcome.server_selected_group, iana::constants::secp256r1);
    assert!(outcome.hello_retry_request);
}
