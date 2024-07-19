# Regression Testing for s2n-tls

This folder contains regression tests and benchmarking tools for the `s2n-tls` library. The tests focus on various aspects of TLS connections.

## Testing Philosophy

Currently, s2n-tls implements a wall clock benchmarking tool which measures end-to-end handshake performance to compare s2n-tls with rustls and OpenSSL. In the past, s2n-tls has tried benchmarking to detect regressions through criterion in Rust, but the subprocess and spin-up time contributed to performance measurement which made the results inaccurate and difficult to use in CI. The project has a slightly different focus, learning from these existing tools. Performance assertion in s2n-tls focuses on a benchmarking tool that can detail performance by API path and do so with enough repeatability and accuracy to detect regressions between two versions of s2n-tls so that performance analysis can occur at PR time. This means that the scope of each harness is limited and mutually exclusive of other harnesses since we are intersted in measuring the performance of the important paths a TLS connection typically follows. 
## Contents

1. **lib.rs**
   - **test_set_config**: Builds a new s2n-tls config with a security policy, host callback and certs
   - **test_rsa_handshake**: Performs an RSA handshake in s2n-tls.

2. **Cargo.toml**
   - The configuration file for building and running the regression tests using Cargo.


## Prerequisites

Ensure you have the following installed:
- Rust (with Cargo)
- Valgrind (for cachegrind instrumentation)

## Running the Harnesses with Valgrind (scalar performance)
To run the harnesses with Valgrind and store the annotated results, run:

```
ENABLE_VALGRIND = true cargo test
```

This will recursively call all tests with valgrind enabled so the performance output is generated and stored
## Running the tests w/o Valgrind

```
cargo test
```

This will run the tests without valgrind to test if the process completes as expected
## Sample Output for Valgrind test

Running the test will run all harnesses and fail if any number of harnesses exceed the performance threshold. For example, a regression test faliure could look like:
```
---- tests::test_set_security_policy_and_build stdout ----
Running command: valgrind --tool=cachegrind --cachegrind-out-file=cachegrind_test_set_security_policy_and_build.out /home/ubuntu/proj/s2n/tests/regression/target/debug/deps/regression-7c7d86aeafe3b426 test_set_security_policy_and_build
Running command: cg_annotate cachegrind_test_set_security_policy_and_build.out > perf_outputs/test_set_security_policy_and_build.annotated.txt
thread 'tests::test_set_security_policy_and_build' panicked at src/lib.rs:174:9:
Instruction count difference in test_set_security_policy_and_build exceeds the threshold, regression of 13975865 instructions
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

---- tests::test_rsa_handshake stdout ----
Running command: valgrind --tool=cachegrind --cachegrind-out-file=cachegrind_test_rsa_handshake.out /home/ubuntu/proj/s2n/tests/regression/target/debug/deps/regression-7c7d86aeafe3b426 test_rsa_handshake
Running command: cg_annotate cachegrind_test_rsa_handshake.out > perf_outputs/test_rsa_handshake.annotated.txt
thread 'tests::test_rsa_handshake' panicked at src/lib.rs:174:9:
Instruction count difference in test_rsa_handshake exceeds the threshold, regression of 51176459 instructions


failures:
    tests::test_rsa_handshake
    tests::test_set_security_policy_and_build
```

It also produces annotated cachegrind files stored in the `perf_ouput` directory which detail the instruction counts, how many instructions a particular file/function account for, and the contribution of individual lines of code to the overall instruction count. For example, these are the first few lines of the output generated for 'test_rsa_handshake.annotated.txt':

```
--------------------------------------------------------------------------------
-- Summary
--------------------------------------------------------------------------------
Ir_________________ 

79,270,744 (100.0%)  PROGRAM TOTALS

--------------------------------------------------------------------------------
-- File:function summary
--------------------------------------------------------------------------------
  Ir_______________________  file:function

< 71,798,872 (90.6%, 90.6%)  /home/ubuntu/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.19.0/aws-lc/generated-src/linux-x86_64/crypto/fipsmodule/x86_64-mont5.S:
  54,908,926 (69.3%)           aws_lc_0_19_0_bn_sqr8x_internal
  15,699,024 (19.8%)           mul4x_internal
   1,114,840  (1.4%)           __bn_post4x_internal

<  1,551,316  (2.0%, 92.5%)  /home/ubuntu/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.19.0/aws-lc/generated-src/linux-x86_64/crypto/fipsmodule/p256-x86_64-asm.S:
     676,336  (0.9%)           __ecp_nistz256_mul_montq
     475,750  (0.6%)           __ecp_nistz256_sqr_montq
      95,732  (0.1%)           aws_lc_0_19_0_ecp_nistz256_point_double

<    833,553  (1.1%, 93.6%)  /home/ubuntu/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.19.0/aws-lc/generated-src/linux-x86_64/crypto/fipsmodule/sha256-x86_64.S:
     830,671  (1.0%)           sha256_block_data_order_avx

<    557,697  (0.7%, 94.3%)  /home/ubuntu/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.19.0/aws-lc/generated-src/linux-x86_64/crypto/fipsmodule/x86_64-mont.S:
     493,032  (0.6%)           bn_mul4x_mont

```

### Understanding the Annotated Output
The total instruction counts are listed at the top, and segmented by file:function beneath it. When comparing versions of s2n-tls (during PR workflow or otherwise) this can be useful to pinpoint the source of instruction count difference to inform you on how changes to the code impact performance. This [link](https://valgrind.org/docs/manual/cg-manual.html#cg-manual.running-cg_annotate:~:text=Information%20Source%20Code%20Documentation%20Contact%20How%20to%20Help%20Gallery,5.2.3.%C2%A0Running%20cg_annotate,-Before%20using%20cg_annotate) provides a more detailed description to fully understand the output file. 

## Test Details

### test_set_config

Configures and creates a new s2n-tls configuration with a specified security policy and loads a certificate key pair. Ensures the configuration is valid and can be built.

### test_rsa_handshake

Performs an RSA handshake in s2n-tls and validates the handshake process utilizing rsa_4096_sha512.
