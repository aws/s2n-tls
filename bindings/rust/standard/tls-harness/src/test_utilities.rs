// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    harness::{TlsConfigBuilder, TlsConfigBuilderPair},
    TlsConnPair, TlsConnection,
};

/// Perform a simple server-auth handshake.
pub fn handshake<C, B>()
where
    C: TlsConnection,
    B: TlsConfigBuilder<Config = C::Config>,
{
    let mut conn_pair: TlsConnPair<C, C> = {
        let config_pair: TlsConfigBuilderPair<B, B> = TlsConfigBuilderPair::default();
        config_pair.connection_pair()
    };
    conn_pair.handshake().unwrap();
    conn_pair.round_trip_transfer(&mut [0]).unwrap();
    conn_pair.shutdown().unwrap();
}

/// Round-trip-transfer 1 MB of data.
pub fn transfer<C, B>()
where
    C: TlsConnection,
    B: TlsConfigBuilder<Config = C::Config>,
{
    let mut conn_pair: TlsConnPair<C, C> = {
        let config_pair: TlsConfigBuilderPair<B, B> = TlsConfigBuilderPair::default();
        config_pair.connection_pair()
    };
    conn_pair.handshake().unwrap();
    let mut data = [0; 1_000_000];
    conn_pair.round_trip_transfer(&mut data).unwrap();
    conn_pair.shutdown().unwrap();
}
