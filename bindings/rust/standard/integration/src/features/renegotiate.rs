use std::io::{Read, Write};

use openssl::ssl::{SslContextBuilder, SslVerifyMode, SslVersion};
use s2n_tls::{enums::ClientAuthType, renegotiate::RenegotiateResponse, security::Policy};
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::{
        read_to_bytes, PemType, SigType, TlsConfigBuilder, TlsConfigBuilderPair, TlsConnPair,
        TlsConnection,
    },
    openssl_extension::{SslExtension, SslStreamExtension},
};

fn renegotiate_pair(
    pair: &mut TlsConnPair<S2NConnection, OpenSslConnection>,
    app_data: Option<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // schedule the renegotiate request
    pair.server.connection.mut_ssl().renegotiate();
    assert!(pair.server.connection.ssl().renegotiate_pending());

    // send the renegotiate request
    let _ = pair.server.connection.write(&[]);

    // read the renegotiate request & send the renegotiation client hello
    let _ = pair.client.connection_mut().poll_recv(&mut [0]);

    if let Some(data) = &app_data {
        // server sends application data before sending the server hello
        let _ = pair.server.connection.write(&data);
    }

    // send the server hello
    let _ = pair.server.connection.read(&mut [0]);

    if let Some(data) = &app_data {
        // client receives application data
        let mut buffer = [0; 1_024];
        assert!(data.len() < buffer.len());
        let _ = pair
            .client
            .connection_mut()
            .poll_recv(&mut buffer[0..data.len()]);
        assert_eq!(&buffer[0..data.len()], data);
    }

    // client sends key material + finished
    let _ = pair.client.connection_mut().poll_recv(&mut [0]);

    // server sends finished
    let _ = pair.server.connection.read(&mut [0]);

    // client reads finished
    let _ = pair.client.connection_mut().poll_recv(&mut [0]);

    // the request is no longer pending, because s2n-tls accepted it
    assert!(!pair.server.connection.ssl().renegotiate_pending());
    Ok(())
}
#[test]
fn s2n_client_renegotiation_is_patched() {
    let mut configs: TlsConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
        TlsConfigBuilderPair::default();
    configs.set_cert(SigType::Ecdsa256);
    configs
        .client
        .set_security_policy(&Policy::from_version("default").unwrap())
        .unwrap();

    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

    assert!(pair.handshake().is_ok());
    assert!(pair.server.connection.ssl().secure_renegotiation_support());
}

/// Renegotiation request ignored by s2n-tls client
///
/// This tests the default behavior for customers who do not enable renegotiation.
#[test]
fn s2n_client_ignores_openssl_renegotiate_request() -> Result<(), Box<dyn std::error::Error>> {
    let mut configs: TlsConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
        TlsConfigBuilderPair::default();
    configs.set_cert(SigType::Ecdsa256);
    configs
        .client
        .set_security_policy(&Policy::from_version("default").unwrap())
        .unwrap();
    configs
        .server
        .set_max_proto_version(Some(SslVersion::TLS1_2))?;

    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

    assert!(pair.handshake().is_ok());

    // schedule and send the renegotiate request
    pair.server.connection.mut_ssl().renegotiate();
    pair.server.send(&[0]);
    assert!(pair.server.connection.ssl().renegotiate_pending());
    assert!(!pair.io.server_tx_stream.borrow().is_empty());

    // do some client IO to recv and potentially respond to the request
    pair.round_trip_assert(1_024).unwrap();
    pair.round_trip_assert(1_024).unwrap();

    // the request is still pending, because s2n-tls ignored it
    assert!(pair.server.connection.ssl().renegotiate_pending());

    pair.shutdown().unwrap();
    Ok(())
}

/// Renegotiation request rejected by s2n-tls client.
#[test]
fn s2n_client_rejects_openssl_hello_request() -> Result<(), Box<dyn std::error::Error>> {
    let mut configs: TlsConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
        TlsConfigBuilderPair::default();
    configs.set_cert(SigType::Ecdsa256);
    configs
        .client
        .set_security_policy(&Policy::from_version("default")?)?
        .set_renegotiate_callback(RenegotiateResponse::Reject)?;
    configs
        .server
        .set_max_proto_version(Some(SslVersion::TLS1_2))?;

    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

    pair.handshake()?;

    // schedule & send the renegotiate request
    pair.server.connection.mut_ssl().renegotiate();
    pair.server.send(&[0]);
    assert!(pair.server.connection.ssl().renegotiate_pending());
    assert!(!pair.io.server_tx_stream.borrow().is_empty());

    // perform a recv call to read the renegotiation request
    pair.client.recv(&mut [0]).unwrap();
    // perform a send call to send the rejection
    pair.client.send(&mut [0]);

    let server_error = pair.server.recv(&mut [0]).unwrap_err();
    assert!(server_error.to_string().contains("no renegotiation"));

    pair.client.recv(&mut [0]).unwrap_err();
    assert_eq!(pair.client.connection().alert(), Some(40));
    Ok(())
}

/// Renegotiation request accepted by s2n-tls client.
#[test]
fn s2n_client_renegotiate_with_openssl() -> Result<(), Box<dyn std::error::Error>> {
    let mut configs: TlsConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
        TlsConfigBuilderPair::default();
    configs.set_cert(SigType::Ecdsa256);
    configs
        .client
        .set_security_policy(&Policy::from_version("default").unwrap())?
        .set_renegotiate_callback(RenegotiateResponse::Schedule)?;
    configs
        .server
        .set_max_proto_version(Some(SslVersion::TLS1_2))?;

    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

    pair.handshake()?;
    pair.round_trip_assert(1_024)?;
    renegotiate_pair(&mut pair, None)?;
    pair.round_trip_assert(1_024)?;
    pair.shutdown()?;

    Ok(())
}

/// Renegotiation request with client auth accepted by s2n-tls client.
///
/// The openssl server does not require client auth during the first handshake,
/// but does require client auth during the second handshake.
#[test]
fn s2n_client_renegotiate_with_client_auth_with_openssl(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut configs: TlsConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
        TlsConfigBuilderPair::default();
    configs.set_cert(SigType::Ecdsa256);
    configs
        .client
        .set_security_policy(&Policy::from_version("default")?)?
        .set_renegotiate_callback(RenegotiateResponse::Schedule)?
        .set_client_auth_type(ClientAuthType::Optional)?
        .load_pem(
            read_to_bytes(PemType::ClientCertChain, SigType::Ecdsa256).as_slice(),
            read_to_bytes(PemType::ClientKey, SigType::Ecdsa256).as_slice(),
        )?;
    configs
        .server
        .set_max_proto_version(Some(SslVersion::TLS1_2))?;
    configs.server.set_trust(SigType::Ecdsa256);

    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();

    pair.handshake()?;

    // require client auth for the renegotiation
    pair.server
        .connection
        .mut_ssl()
        .set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);

    renegotiate_pair(&mut pair, None)?;
    pair.round_trip_assert(1_024)?;
    pair.shutdown()?;

    Ok(())
}

/// The s2n-tls client successfully reads ApplicationData during the renegotiation handshake.
#[test]
fn s2n_client_renegotiate_with_app_data_with_openssl() -> Result<(), Box<dyn std::error::Error>>
{
    let mut configs: TlsConfigBuilderPair<s2n_tls::config::Builder, SslContextBuilder> =
        TlsConfigBuilderPair::default();
    configs.set_cert(SigType::Ecdsa256);
    configs
        .client
        .set_security_policy(&Policy::from_version("default")?)?
        .set_renegotiate_callback(RenegotiateResponse::Schedule)?;

    // Renegotiation is TLS 1.2-only.
    configs
        .server
        .set_max_proto_version(Some(SslVersion::TLS1_2))?;

    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = configs.connection_pair();
    pair.handshake()?;

    renegotiate_pair(&mut pair, Some(Vec::from(b"some application data")))?;
    pair.round_trip_assert(1_024)?;
    pair.shutdown()?;
    Ok(())
}
