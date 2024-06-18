// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use pcap::all_pcaps;
use pcap::client_hello::ClientHello as PcapHello;
use pcap::handshake_message::Builder;
use s2n_tls::client_hello::{ClientHello as S2NHello, FingerprintType};

fn get_s2n_hello(pcap_hello: &PcapHello) -> Result<Box<S2NHello>> {
    let bytes = pcap_hello.message().bytes();
    let r = S2NHello::parse_client_hello(&bytes);
    println!("Result: {:?}", r);
    Ok(r?)
}

fn test_all_client_hellos<F>(test_fn: F) -> Result<()>
where
    F: FnOnce(PcapHello, Box<S2NHello>) -> Result<()> + Copy,
{
    let pcaps = all_pcaps();
    for pcap in pcaps {
        let mut builder = Builder::default();
        builder.set_capture_file(&pcap);
        let hellos = builder.build_client_hellos()?;

        for hello in hellos {
            println!(
                "Testing ClientHello found in frame {} in {}",
                hello.message().packet.id(),
                pcap
            );
            let s2n_hello = get_s2n_hello(&hello).context("s2n failed to parse ClientHello")?;
            test_fn(hello, s2n_hello)?;
        }
    }
    Ok(())
}

#[test]
fn parsing() -> Result<()> {
    test_all_client_hellos(|_, _| Ok(()))
}

#[test]
fn ja3_fingerprints() -> Result<()> {
    test_all_client_hellos(|pcap_hello, s2n_hello| {
        let mut s2n_ja3_hash = Vec::new();
        s2n_hello
            .fingerprint_hash(FingerprintType::JA3, &mut s2n_ja3_hash)
            .context("s2n failed to calculate ja3 hash")?;
        let s2n_ja3_hash = hex::encode(s2n_ja3_hash);

        let mut s2n_ja3_str = String::with_capacity(1000);
        s2n_hello
            .fingerprint_string(FingerprintType::JA3, &mut s2n_ja3_str)
            .context("s2n failed to calculate ja3 string")?;

        assert_eq!(pcap_hello.ja3_hash(), Some(s2n_ja3_hash));
        assert_eq!(pcap_hello.ja3_string(), Some(s2n_ja3_str));
        Ok(())
    })
}
