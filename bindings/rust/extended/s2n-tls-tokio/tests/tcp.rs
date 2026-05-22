// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod common;

async fn assert_read_from_closed<S>(mut reader: S, writer: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    drop(writer);
    let result = reader.read_u8().await;
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.kind() == std::io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn match_tcp_read_from_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (tcp_server, tcp_client) = common::get_streams().await?;
    assert_read_from_closed(tcp_server, tcp_client).await;

    let (tls13_server, tls13_client) = common::get_tls_streams(
        common::server_config()?.build()?,
        common::client_config()?.build()?,
    )
    .await?;
    assert_read_from_closed(tls13_server, tls13_client).await;

    let (tls12_server, tls12_client) = common::get_tls_streams(
        common::server_config_tls12()?.build()?,
        common::client_config_tls12()?.build()?,
    )
    .await?;
    assert_read_from_closed(tls12_server, tls12_client).await;
    Result::Ok(())
}

async fn assert_write_to_closed<S>(reader: S, mut writer: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    drop(reader);
    let result = writer.write_u8(0).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn match_tcp_write_to_closed() -> Result<(), Box<dyn std::error::Error>> {
    let (tcp_server, tcp_client) = common::get_streams().await?;
    assert_write_to_closed(tcp_server, tcp_client).await;

    let (tls13_server, tls13_client) = common::get_tls_streams(
        common::server_config()?.build()?,
        common::client_config()?.build()?,
    )
    .await?;
    assert_write_to_closed(tls13_server, tls13_client).await;

    let (tls12_server, tls12_client) = common::get_tls_streams(
        common::server_config_tls12()?.build()?,
        common::client_config_tls12()?.build()?,
    )
    .await?;
    assert_write_to_closed(tls12_server, tls12_client).await;
    Result::Ok(())
}
