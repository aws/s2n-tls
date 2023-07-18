# Benchmarking s2n-tls

We use to Criterion.rs to benchmark s2n-tls against two commonly used TLS libraries, Rustls and OpenSSL.

## Setup 

Setup is easy! Just have OpenSSL installed and generate Rust bindings for s2n-tls using `bindings/rust/generate.sh`.

## Running benchmarks

The benchmarks can be run with the `cargo bench` command. Criterion will auto-generate an HTML report in `target/criterion/`. 

## Historical benchmarks

To do historical benchmarks, run `historical-perf/bench-past.sh`. This will checkout old versions of s2n-tls back to v1.3.16 in `target/` and run benchmarks on those with the `historical-perf` feature, disabling Rustls and OpenSSL benches.

### Caveats

The last version benched is v1.3.16, since before that, the s2n-tls Rust bindings have a different API and would thus require a different bench harness to test. 

v1.3.30-1.3.37 are not benched because of depedency issues when generating the Rust bindings. However, versions before and after are benched, so the overall trend in performance can still be seen without the data from these versions.

## Implementation details

We use Rust bindings for s2n-tls and OpenSSL. All of our benchmarks are run in Rust on a single thread for consistency. 

### IO

To remove external factors, we use custom IO with our benchmarks, bypassing the networking layer and having the client and server connections transfer data to each other via a local buffer. 

### Certificate generation

All certs are stored in `certs/` and can be regenerated using `certs/generate_certs.sh`. There is one root cert that directly signs the server and client certs that are used in benchmarking. Currently, we use ECDSA with `secp384r1`.

### Negotiation parameters

The cipher suites benchmarked are `TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384`, and the key exchange methods benchmarked are ECDHE with `secp256r1` and with `x25519`. We also test connections with and without client authentication (mTLS).

## Sample output

### Historical performance

Because these benches take a longer time to generate (>30 min), we include the results from historical benching here.

Notes: 
- Two sets of parameters for the handshake couldn't be benched before 1.3.40, since security policies that negotiated those policies as their top choice did not exist before then.
- There is no data from 1.3.30 to 1.3.37 because those versions have a dependency issue that cause the Rust bindings not to build. However, there is data before and after that period, so the performance for those versions can be inferred via interpolation.
- The improvement in throughput in 1.3.28 was most likely caused by the addition of LTO to the default Rust bindings build. 
- Since the benches are run over a long time, noise on the machine can cause variability, as seen in the throughput graph.
- The variability can be seen with throughput especially because it is calculated as the inverse of time taken.

![historical-perf-handshake](https://github.com/tinzh/s2n-tls/assets/76919968/b6448634-e6d1-4724-ab91-7efc26485274)

![historical-perf-throughput](https://github.com/tinzh/s2n-tls/assets/76919968/3bc069f6-abe8-46e6-97a6-1bf28ac59f28)
