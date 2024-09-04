// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use bytes::Buf;
use bytes::Bytes;
use std::collections::HashMap;
use std::fs::File;
use std::io::copy;
use std::path::Path;
use std::thread;
use std::time::Duration;

fn get_download_urls() -> HashMap<String, String> {
    let mut urls = HashMap::new();
    if cfg!(feature = "download") == false {
        return urls;
    }

    let ja4_pcaps = [
        "badcurveball.pcap",
        "browsers-x509.pcapng",
        "chrome-cloudflare-quic-with-secrets.pcapng",
        "http2-with-cookies.pcapng",
        "ipv6.pcapng",
        "latest.pcapng",
        "macos_tcp_flags.pcap",
        "tls-alpn-h2.pcap",
        // TODO: non-ascii alpn handling currently differs between implementations,
        // with no official consensus. Wireshark chose different handling than s2n-tls did.
        // See https://github.com/FoxIO-LLC/ja4/pull/147
        // "tls-non-ascii-alpn.pcapng",
        "tls12.pcap",
        "tls3.pcapng",
    ];
    add_github_urls(
        &mut urls,
        "FoxIO-LLC/ja4",
        "259739593049478dc68c84a436eca75b9f404e6e",
        "pcap",
        &ja4_pcaps,
    );

    let wireshark_pcaps = [
        "tls-renegotiation.pcap",
        "tls12-aes128ccm.pcap",
        "tls12-aes256gcm.pcap",
        "tls12-chacha20poly1305.pcap",
        "tls12-dsb.pcapng",
        "tls13-20-chacha20poly1305.pcap",
        "tls13-rfc8446.pcap",
        "rsa-p-lt-q.pcap",
        "rsasnakeoil2.pcap",
        "http2-brotli.pcapng",
    ];
    add_github_urls(
        &mut urls,
        "wireshark/wireshark",
        "2ba9f4c56e162127b85164912399b8e69e47b1d3",
        "test/captures",
        &wireshark_pcaps,
    );

    urls
}

fn add_github_urls(
    output: &mut HashMap<String, String>,
    repo: &str,
    commit: &str,
    path: &str,
    files: &[&str],
) {
    // For safety, only exact commits can be used. No tags or branches.
    assert!(commit.len() == 40);
    assert!(hex::decode(commit).is_ok());

    for file in files {
        let url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}/{}",
            repo, commit, path, file
        );
        let name = format!("{}_{}", repo.replace('/', "_"), file);
        if output.insert(name, url).is_some() {
            panic!("Duplicate download path for {repo}:{file}")
        }
    }
}

fn download(url: &str) -> Result<Bytes> {
    let delay = Duration::from_secs(5);
    for _ in 0..5 {
        if let reqwest::Result::Ok(result) = reqwest::blocking::get(url) {
            if let reqwest::Result::Ok(bytes) = result.bytes() {
                return Ok(bytes);
            }
        }
        delay.checked_mul(2).context("Invalid backoff delay")?;
        thread::sleep(delay);
    }
    bail!("Unable to download: {}", url);
}

fn main() -> Result<()> {
    let out_dir = std::env::var("OUT_DIR")?;
    let download_path = Path::new(&out_dir).join("downloaded_pcaps");

    let _ = std::fs::remove_dir_all(&download_path);
    std::fs::create_dir_all(&download_path).context("Failed to create path")?;
    println!(
        "Created directory for downloaded pcaps: {}",
        download_path.display()
    );

    let urls = get_download_urls();
    for (name, url) in urls {
        let contents = download(&url)?;
        let file_path = download_path.join(name);
        let mut file = File::create(&file_path)?;
        copy(&mut contents.reader(), &mut file)?;
        println!("Downloaded pcap \"{}\" to {}", url, file_path.display());
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rustc-env=DOWNLOADED_PCAPS_PATH={}",
        download_path.display()
    );

    Ok(())
}
