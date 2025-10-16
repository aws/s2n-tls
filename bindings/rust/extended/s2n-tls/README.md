# s2n-tls

s2n-tls is a C99 implementation of the TLS protocol. This crate provides idiomatic Rust bindings for the underlying C library. For additional Rust ecosystem integrations see
- [s2n-tls-tokio](https://crates.io/crates/s2n-tls-tokio): integrations for the tokio async runtime
- [s2n-tls-hyper](https://crates.io/crates/s2n-tls-hyper): integrations for the hyper HTTP library

## Features
- SSLv3 - TLS 1.3
- PQ algorithms including ML-KEM and ML-DSA
- TLS 1.2 stateful and stateless session resumption
- TLS 1.3 stateless session resumption
- Early Data
- TLS 1.3 PSK Authentication
- Private Key offload
- JA3 and JA4 client hello fingerprinting

## Build

Consuming projects will need a C compiler (Clang or GCC) to build. 

If "fips" is enabled, then consuming projects will also need **CMake** and **Go** due to the underlying AWS-LC-FIPS dependency.

## Cryptography Provider

By default, the s2n-tls bindings will rely on [aws-lc-rs](https://crates.io/crates/aws-lc-rs) for cryptography. To use a FIPS validated libcrypto, customers can enable the `fips` feature flag in `s2n-tls`. This enables the `fips` feature in the underlying AWS-LC libcrypto.