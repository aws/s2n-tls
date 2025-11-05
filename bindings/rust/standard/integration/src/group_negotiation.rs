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
    configured_openssl_groups: String,
}

impl Trial {
    /// Indicate the groups to set on the openssl client, e.g. "SecP384r1MLKEM1024"
    fn new(groups: String) -> Self {
        Self {
            configured_openssl_groups: groups
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

impl Trial {
    fn handshake(&self) -> Outcome {
        let key_manager = KeyManager::new();
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs
                .server
                .set_security_policy(&Policy::from_version("20251014").unwrap())
                .unwrap();
            key_manager.enable_s2n_logging(&mut configs.server);
            configs.client.set_groups_list(&self.configured_openssl_groups).unwrap();
            configs.connection_pair()
        };
        pair.io.enable_recording();
        pair.io.enable_decryption(key_manager.clone());

        pair.handshake().unwrap();
        pair.shutdown().unwrap();

        let mut transcript = pair.io.decrypter.lock().unwrap();
        let transcript = transcript.as_mut().unwrap().transcript();
        let ch = transcript.client_hellos().first().unwrap().clone();
        println!("{ch:#?}");
        let key_shares = ch.key_share().unwrap();
        let supported_groups = ch.supported_groups().unwrap();

        let sh = transcript.server_hello();
        Outcome {
            client_key_shares: key_shares,
            client_supported_groups: supported_groups,
            server_selected_group: sh.selected_group().unwrap().unwrap(),
            hello_retry_request: transcript.hello_retry_request().is_some()
        }
    }
}

/// Classical Key Share Preference:
///
/// When s2n-tls receives a key share from the client AND that group is allowed
/// by the security policy, it will choose that group even if it isn't the highest
/// server preference.
#[test]
fn classical_group_selection() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // client prefers secp256r1
    let trial = Trial::new("secp256r1:secp384r1:secp521r1".to_owned());
    let outcome = trial.handshake();
    println!("outcome: {outcome:?}");
    assert_eq!(outcome.client_key_shares, vec![iana::constants::secp256r1]);
    assert_eq!(outcome.server_selected_group, iana::constants::secp256r1);
    assert!(!outcome.hello_retry_request);

    let trial = Trial::new("secp384r1:secp521r1:secp256r1".to_owned());
    let outcome = trial.handshake();
    println!("outcome: {outcome:?}");
    assert_eq!(outcome.client_key_shares, vec![iana::constants::secp384r1]);
    assert_eq!(outcome.server_selected_group, iana::constants::secp384r1);
    assert!(!outcome.hello_retry_request);


    let trial = Trial::new("secp521r1:secp256r1:secp384r1".to_owned());
    let outcome = trial.handshake();
    println!("outcome: {outcome:?}");
    assert_eq!(outcome.client_key_shares, vec![iana::constants::secp521r1]);
    assert_eq!(outcome.server_selected_group, iana::constants::secp521r1);
    assert!(!outcome.hello_retry_request);

}

#[test]
fn hello_retry_request() {
    // client prefers secp256r1
    let trial = Trial::new("x448:secp384r1".to_owned());
    let outcome = trial.handshake();
    println!("outcome: {outcome:?}");
    assert_eq!(outcome.client_key_shares, vec![iana::constants::x448]);
    assert_eq!(outcome.server_selected_group, iana::constants::secp384r1);
    assert!(outcome.hello_retry_request);
}

/// PQ Key Share Preference:
///
/// When s2n-tls receives a key share from the client AND that group is allowed
/// by the security policy, it will choose that group even if it isn't the highest
/// server preference.
#[test]
fn pq_group_selection() {}
