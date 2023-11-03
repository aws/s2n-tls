+++
title = 'Platform support'
date = 2023-10-05T12:13:46-07:00
weight = 11
draft = false
+++

## Tier 1 (Supported and tested)

Tier 1 targets can be thought of as "guaranteed to work". The Rust project builds official binary releases for each tier 1 target, and automated testing ensures that each tier 1 target builds and passes tests after each change.

target triplet (o build triplet)
architecture-vendor-operating system
/processor/-/distribution/-/
https://git.savannah.gnu.org/cgit/libtool.git/tree/doc/PLATFORMS

Target                            | Notes
----------------------------------|------------------------------
x86_64-ubuntu-linux-gnu           | Ubuntu 22 LTS (forthcoming)
x86_64-ubuntu-linux-gnu           | Ubuntu 18 LTS
x86_64-unknown-freebsd*           | freeBSD 13.2
x86_64-apple-darwin               | ARM64 macOS (11.0+, Big Sur+)
amazonlinux2-aarch64-standard:2.0 | Amazon Linux 2 ARM
amazonlinux2-x86_64-standard:3.0  | Amazon Linux 2

\* We don't specify an architecture in ci_freebsd.yml so it is possible that we're testing amd64 ? The freebsd CI image is https://download.freebsd.org/releases/CI-IMAGES/13.2-RELEASE/
  
## Tier 2

Tier 2 targets can be thought of as "guaranteed to build". Automated tests for these build targets are incomplete or infrequently run.

Target            | Notes
------------------------|--------------------------------
x86_64-ubuntu-linux-gnu | Ubuntu 14 LTS
aarch64-apple-darwin    | ARM64 macOS (11.0+, Big Sur+)
x86_64-unknown-openbsd  | OpenBSD 7.2 AMD64-based systems

## Tier 3

The s2n-tls project does not build or test automatically for tier 3 targets, so they may or may not work.

Target                          | Notes
--------------------------------------|--------------------
powerpc-unknown-linux-gnu             | unsupported
CentOS-Stream-8-20231002.0-x86_64.iso | CentOS
x86_64-unknown-linux-gnu               | Fedora
x86_64-unknown-linux-gnu               | Debian
x86_64-unknown-linux-gnu               | RHEL
x86_64-unknown-linux-gnu               | Amazon Linux 2023
x86_64-ubuntu-linux-gnu               | Ubuntu 16

## Runtime

## Buildtime

## Supported TLS versions

Currently TLS 1.2 is our default version, but we recommend TLS 1.3 where possible. To use TLS 1.3 you need a security policy that supports TLS 1.3. See the [Security Policies](#security-policies) section for more information.

**Note:** s2n-tls does not support SSL2.0 for sending and receiving encrypted data, but does accept SSL2.0 hello messages.