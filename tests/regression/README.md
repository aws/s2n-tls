# Regression Testing for s2n-tls

This folder contains regression tests and benchmarking tools for the `s2n-tls` library. The tests focus on various aspects of TLS connections. 


## Testing Philosophy

Currently, s2n-tls implements a wall clock benchmarking tool which measures end-to-end handshake performance to compare s2n-tls with rustls and OpenSSL. In the past, s2n-tls has tried benchmarking to detect regressions through criterion in Rust, but the subprocess and spin-up time contributed to performance measurement which made the results inaccurate and difficult to use in CI. The project has a slightly different focus, learning from these existing tools. Performance assertion in s2n-tls focuses on a benchmarking tool that can detail performance by API path and do so with enough repeatability and accuracy to detect regressions between two versions of s2n-tls so that performance analysis can occur at PR time. This means that the scope of each harness is limited and mutually exclusive of other harnesses since we are interested in measuring the performance of the important paths a TLS connection typically follows. 

### Why CPU instructions
The performance benchmarking framework utilizes CPU Instruction count across API paths to make the regression assertion. This technique reduces noise, ensuring that small performance differences are caught through this measure. While a difference in performance count may not result in a direct runtime difference, it is useful when comparing a PR to mainline and to dig into the specific sources of performance impact within the code. 

## Contents

1. **lib.rs**
   - **test_set_config**: Builds a new s2n-tls config with a security policy, host callback and certs
   - **test_rsa_handshake**: Performs an RSA handshake in s2n-tls.
   - **test_session_resumption**: Does two handshakes, the first handshake provides a session ticket, and then that session ticket is used to resume in the second handshake.

2. **Cargo.toml**
   - The configuration file for building and running the regression tests using Cargo.


## Prerequisites

Ensure you have the following installed:
- Rust (with Cargo)
- Valgrind (for cachegrind instrumentation): Valgrind 3.23 or newer is required to run the tests, since cachegrind annotation is not included in earlier versions. If this version is not automatically downloaded by running `apt install valgrind`, it can be installed manually by following https://valgrind.org/downloads/

## Running the Harnesses with Valgrind (scalar performance)
To run the harnesses with Valgrind and store the annotated results, run:

```
PERF_MODE=valgrind cargo test
```

This will recursively call all tests with valgrind enabled so the performance output is generated and stored in target/perf_outputs. If you are looking for the scalar performance output of a PR, this will provide insight into which portions of the code account for what share of the CPU instruction count.

## Running the Harnesses between versions (differential performance)
Run the scalar performance for all harnesses on the current branch version of s2n-tls
```
PERF_MODE=valgrind cargo test
```
`git checkout` or `git switch` to mainline/version being compared to. Make sure you have stashed or committed any changes.
```
PERF_MODE=valgrind cargo test
```
`git checkout` or `git switch` back to the original version. At this point you should have two annotated performance outputs for each test. If you have more, the diff test will not be able to recognize the versions being compared.
```
PERF_MODE=diff cargo test
```
This will assert on the performance difference of the current version minus the previous. If the regression exceeds the const `MAX_DIFF`, the test fails. Performance output profiles are stored by their commit id in `/target/commit_id`:
- `raw_profile` for the unannotated cachegrind output result
- `annotated_profile` for the annotated cachegrind output (scalar)
- `target/diff` contains the annotated differential profile between two commits

## Running the tests w/o Valgrind

```
cargo test
```

This will run the tests without valgrind to test if the harnesses complete as expected

## Output Files
- `target/$commit_id/test_name.raw`: Contains the raw cachegrind profile. On its own, the file is pretty much unreadable but is useful for the cg_annotate --diff functionality or to visualize the profile via tools like [KCachegrind](https://kcachegrind.github.io/html/Home.html).
- `target/$commit_id/test_name.annotated`: The scalar annotated profile associated with that particular commit id. This file contains detailed information on the contribution of functions, files, and lines of code to the overall scalar performance count.
- `target/diff/test_name.diff`: The annotated performance difference between two commits. This file contains the overall performance difference and also details the instruction counts, how many instructions a particular file/function account for, and the contribution of individual lines of code to the overall instruction count difference.

## Sample Output for Valgrind test (differential)

Running the differential test will run all harnesses and fail if any number of harnesses exceed the performance threshold. For example, a regression test failure could look like:
```
running 2 tests
test tests::test_set_config ... FAILED
test tests::test_rsa_handshake ... ok

failures:

---- tests::test_set_config stdout ----
Instruction difference for test_set_config: 245746
thread 'tests::test_set_config' panicked at src/lib.rs:189:9:
Instruction count difference in test_set_config exceeds the threshold, regression of 245746 instructions
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    tests::test_set_config

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
```

### target/diff/test_set_config.diff

```
--------------------------------------------------------------------------------
-- Summary
--------------------------------------------------------------------------------
Ir______________ 

245,746 (100.0%)  PROGRAM TOTALS

--------------------------------------------------------------------------------
-- File:function summary
--------------------------------------------------------------------------------
  Ir______________________  file:function

<  243,774  (99.2%, 99.2%)  /home/ubuntu/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.19.0/aws-lc/crypto/fipsmodule/../internal.h:
    62,034  (25.2%)           constant_time_select_w
    47,264  (19.2%)           value_barrier_w
    47,264  (19.2%)           constant_time_select_int
    25,279  (10.3%)           constant_time_lt_w
    20,692   (8.4%)           constant_time_msb_w
    20,566   (8.4%)           constant_time_is_zero_w
    16,346   (6.7%)           constant_time_eq_w
     2,720   (1.1%)           CRYPTO_addc_u64
       608   (0.2%)           OPENSSL_memcpy
      -504  (-0.2%)           CRYPTO_subc_u64
       480   (0.2%)           CRYPTO_bswap4
       424   (0.2%)           OPENSSL_memset
       315   (0.1%)           CRYPTO_load_u32_be
       270   (0.1%)           CRYPTO_store_u32_be
```

### Understanding the Annotated Output
The total instruction counts are listed at the top, and segmented by file:function beneath it. When comparing versions of s2n-tls (during PR workflow or otherwise) this can be useful to pinpoint the source of instruction count difference to inform you on how changes to the code impact performance. This [link](https://valgrind.org/docs/manual/cg-manual.html#cg-manual.running-cg_annotate:~:text=Information%20Source%20Code%20Documentation%20Contact%20How%20to%20Help%20Gallery,5.2.3.%C2%A0Running%20cg_annotate,-Before%20using%20cg_annotate) provides a more detailed description to fully understand the output file. 

## Test Details

### test_set_config

Configures and creates a new s2n-tls configuration with a specified security policy and loads a certificate key pair. Ensures the configuration is valid and can be built.

### test_rsa_handshake

Performs an RSA handshake in s2n-tls and validates the handshake process utilizing rsa_4096_sha512.

### test_session_resumption

Performs an RSA handshake with server authentication. Then, performs a resumption handshake using the session ticket obtained from the previous handshake.
