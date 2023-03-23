This crates provides low level bindings for [s2n-tls](https://github.com/aws/s2n-tls) created with [bindgen](https://github.com/rust-lang/rust-bindgen)

Rather than developing against the API of this crate, consumers prefer to use the [s2n-tls](https://crates.io/crates/s2n-tls) crate instead. This `s2n-tls` crate providers ergonomic and idiomatic rust bindings for the C `s2n-tls` library.