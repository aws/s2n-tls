// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::connection::Builder;
use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod common;

trait TestStream: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> TestStream for T {}

type TestPair = (Box<dyn TestStream>, Box<dyn TestStream>);
type TestPairList = Vec<TestPair>;
async fn new_test_pairs<A, B>(
    server_builder: A,
    client_builder: B,
) -> Result<TestPairList, Box<dyn std::error::Error>>
where
    A: Builder,
    B: Builder,
    <A as Builder>::Output: Unpin + 'static,
    <B as Builder>::Output: Unpin + 'static,
{
    let mut list: TestPairList = Vec::new();

    let (server_tcp, client_tcp) = common::get_streams().await?;
    list.push((Box::new(server_tcp), Box::new(client_tcp)));

    let (server_stream, client_stream) = common::get_streams().await?;
    let connector = TlsConnector::new(client_builder);
    let acceptor = TlsAcceptor::new(server_builder);
    let (client_tls, server_tls) =
        common::run_negotiate(&connector, client_stream, &acceptor, server_stream).await?;
    list.push((Box::new(server_tls), Box::new(client_tls)));

    Result::Ok(list)
}

#[tokio::test]
async fn match_tcp_read_from_closed() -> Result<(), Box<dyn std::error::Error>> {
    let client_builder = common::client_config()?.build()?;
    let server_builder = common::server_config()?.build()?;
    let test_pairs = new_test_pairs(server_builder, client_builder).await?;
    for (mut reader, writer) in test_pairs {
        drop(writer);
        let result = reader.read_u8().await;
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.kind() == std::io::ErrorKind::UnexpectedEof);
    }
    Result::Ok(())
}

#[tokio::test]
async fn match_tcp_read_from_closed_tls12() -> Result<(), Box<dyn std::error::Error>> {
    let client_builder = common::client_config_tls12()?.build()?;
    let server_builder = common::server_config_tls12()?.build()?;
    let test_pairs = new_test_pairs(server_builder, client_builder).await?;
    for (mut reader, writer) in test_pairs {
        drop(writer);
        let result = reader.read_u8().await;
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.kind() == std::io::ErrorKind::UnexpectedEof);
    }
    Result::Ok(())
}

#[tokio::test]
async fn match_tcp_write_to_closed() -> Result<(), Box<dyn std::error::Error>> {
    let client_builder = common::client_config()?.build()?;
    let server_builder = common::server_config()?.build()?;
    let test_pairs = new_test_pairs(server_builder, client_builder).await?;
    for (mut writer, reader) in test_pairs {
        drop(reader);
        let result = writer.write_u8(0).await;
        assert!(result.is_ok());
    }
    Result::Ok(())
}

#[tokio::test]
async fn match_tcp_write_to_closed_tls12() -> Result<(), Box<dyn std::error::Error>> {
    let client_builder = common::client_config_tls12()?.build()?;
    let server_builder = common::server_config_tls12()?.build()?;
    let test_pairs = new_test_pairs(server_builder, client_builder).await?;
    for (mut writer, reader) in test_pairs {
        drop(reader);
        let result = writer.write_u8(0).await;
        assert!(result.is_ok());
    }
    Result::Ok(())
}
