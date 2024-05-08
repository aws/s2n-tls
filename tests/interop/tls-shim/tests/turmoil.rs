// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use common::InteropTest;

use std::net::{Ipv4Addr, SocketAddrV4};
use tls_shim::{s2n_tls_shim::S2NShim, ClientTLS, ServerTLS};

use turmoil::Sim;

// turmoil's send function seems to be quadratic somewhere. Sending 1 Gb takes
// approximately 229 seconds so don't simulate the large data tests.
const TEST_CASES: [InteropTest; 3] = [
    InteropTest::RequestResponse,
    InteropTest::Handshake,
    InteropTest::MTLSRequestResponse,
];

const PORT: u16 = 1738;

async fn server_loop<T>(test: InteropTest) -> Result<(), Box<dyn std::error::Error>>
where
    T: ServerTLS<turmoil::net::TcpStream>,
{
    let config = T::get_server_config(test)?.unwrap();

    let server = T::acceptor(config);

    let listener =
        turmoil::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).await?;

    let (stream, _peer_addr) = listener.accept().await?;

    let server_clone = server.clone();
    let tls = T::accept(&server_clone, stream).await.unwrap();
    T::handle_server_connection(test, tls).await.unwrap();
    Ok(())
}

async fn client_loop<T>(
    test: InteropTest,
    server_domain: String,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: ClientTLS<turmoil::net::TcpStream>,
{
    let config = T::get_client_config(test)?.unwrap();

    let client = T::connector(config);
    let transport_stream = turmoil::net::TcpStream::connect((server_domain, PORT)).await?;

    let tls = T::connect(&client, transport_stream).await.unwrap();
    T::handle_client_connection(test, tls).await.unwrap();
    Ok(())
}

fn setup_scenario<S, C>(sim: &mut Sim, test: InteropTest)
where
    S: ServerTLS<turmoil::net::TcpStream> + 'static,
    C: ClientTLS<turmoil::net::TcpStream> + 'static,
{
    let server_name = format!(
        "{}-{}-{}-server",
        std::any::type_name::<S>(),
        std::any::type_name::<C>(),
        test
    );
    let client_name = format!(
        "{}-{}-{}-client",
        std::any::type_name::<S>(),
        std::any::type_name::<C>(),
        test
    );
    sim.host(server_name.as_str(), move || server_loop::<S>(test));
    sim.client(client_name, client_loop::<C>(test, server_name));
}

#[test]
fn turmoil_interop() -> turmoil::Result {
    let mut sim = turmoil::Builder::new().build();

    for t in TEST_CASES {
        setup_scenario::<S2NShim, S2NShim>(&mut sim, t);
    }

    sim.run()
}
