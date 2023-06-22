# Benchmarking s2n-tls

We benchmark s2n-tls against two other common TLS libraries, Rustls and OpenSSL. We use Rust bindings for s2n-tls and OpenSSL and Criterion to benchmark these libraries. 

## Setup 

Setup is easy! Just run `/bindings/rust/generate.sh` to generate Rust bindings for s2n-tls and have OpenSSL installed.

## Running benchmarks

To run our results, just run `cargo bench`! Critierion will auto-generate an HTML report in `target/criterion/`. 

## Future features

For these libraries, in the future we plan to benchmark:
- bulk throughput with different cipher suites
- handshakes with client authentication (mTLS)
- handshakes with different certificate signature algorithms
- and session resumption.

We will also conduct memory benchmarks for all features and test the historical performance of s2n-tls.

## Implementation details

All of our benchmarks are run in Rust on a single thread for consistency.

### IO

To remove external factors, we use custom IO with our benchmarks, bypassing the networking layer and having the client and server connections transfer data to each other via a local buffer. 

Because s2n-tls Rust bindings only allows the use of a `*mut c_void` context pointer and callbacks to handle IO, we use a `Pin<Box<UnsafeCell<VecDeque<u8>>>>` for our local buffers, getting the pointer to the context `VecDeque` using `UnsafeCell::get()`. We use `Pin<Box<T>>` to ensure the context pointer passed to s2n-tls is constant and remains valid. We use `UnsafeCell` to wrap the context pointer, and the single-threaded nature of the benchmarks ensures only one connection is mutating the context at once.

### Certificate generation

All certs are stores in `certs/` and can be regenerated using `certs/generate_certs.sh`. There is one root cert that directly signs the server and client certs that are used in benchmarking. Currently, we use ECDSA with secp384r1.

### Cipher suites

The only cipher suites benchmarked are AES-128/GCM/SHA-256 and AES-256/GCM/SHA-384, as these are the most readily usable for all 3 libraries.

### Key exchange algorithms

The only key exchange methods benchmarked are ECDHE with secp256r1 and with x25519, as these are the most readily usable for all 3 libraries.