# Benchmarking s2n-tls

We use to Criterion.rs to benchmark s2n-tls against two commonly used TLS libraries, Rustls and OpenSSL.

## Setup 

Setup is easy! Just have OpenSSL installed, generate Rust bindings for s2n-tls using `../generate.sh`, and generate certs using `certs/generate_certs.sh`. 

Dependencies are the same as with s2n-tls. Currently, this crate has only been tested on Ubuntu (both x86 and ARM), but we expect everything to work with other Unix environments. 

To bench with AWS-LC, Amazon's custom libcrypto implementation, first run `install-aws-lc.sh` to install AWS-LC for the bench crate. To then run the benchmarks with AWS-LC, use Cargo with either the flag `--config aws-lc-config/s2n.toml` or `--config aws-lc-config/rustls.toml` (or both). You can also append these configs to `.cargo/config.toml` to let Cargo automatically detect the settings without specifying the flags each time.  

For example, to get started with benching s2n-tls with AWS-LC:

```
../generate.sh
certs/generate_certs.sh
./install-aws-lc.sh
cargo bench --config aws-lc-config/s2n.toml
```

## Running benchmarks

The benchmarks can be run with the `cargo bench` command. Criterion will auto-generate an HTML report in `target/criterion/`. 

To run memory benchmarks, run `memory/bench-memory.sh`. A graph of memory usage will be generated in `memory/memory.svg`.

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

There is one root cert that directly signs the server and client certs that are used in benchmarking. We currently bench RSA and ECDSA certs.

### Negotiation parameters

The cipher suites benchmarked are `TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384`, and the key exchange methods benchmarked are ECDHE with `secp256r1` and with `x25519`. We also test connections with and without client authentication (mTLS).

## Sample output

### Historical performance

Because these benches take a longer time to generate (>30 min), we include the results from historical benching (as of v1.3.47) here.

Notes: 
- Two sets of parameters for the handshake couldn't be benched before 1.3.40, since security policies that negotiated those policies as their top choice did not exist before then.
- There is no data from 1.3.30 to 1.3.37 because those versions have a dependency issue that cause the Rust bindings not to build. However, there is data before and after that period, so the performance for those versions can be inferred via interpolation.
- The improvement in throughput in 1.3.28 was most likely caused by the addition of LTO to the default Rust bindings build. 
- Since the benches are run over a long time, noise on the machine can cause variability, as seen in the throughput graph.
- The variability can be seen with throughput especially because it is calculated as the inverse of time taken.

![historical-perf-handshake](images/historical-perf-handshake.svg)

![historical-perf-throughput](images/historical-perf-throughput.svg)
