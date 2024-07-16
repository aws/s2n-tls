# Regression Testing for s2n-tls

This folder contains regression tests and benchmarking tools for the `s2n-tls` library. The tests focus on various aspects of TLS connections, including handshakes and session resumptions.

## Testing Philosophy

Currently, s2n-tls implements a wall clock benchmarking tool which measures end-to-end handshake performance to compare s2n-tls with rustls and OpenSSL. In the past, s2n-tls has tried benchmarking to detect regressions through criterion in Rust, but the subprocess and spin-up time contributed to performance measurement which made the results inaccurate and difficult to use in CI. The project has a slightly different focus, learning from these existing tools. Performance assertion in s2n-tls focuses on a benchmarking tool that can detail performance by API path and do so with enough repeatability and accuracy to detect regressions between two versions of s2n-tls so that performance analysis can occur at PR time. This means that the scope of each harness is limited and mutually exclusive of other harnesses since we are intersted in measuring the performance of the important paths a TLS connection typically follows. 
## Contents

1. **Regression Harnesses**
   - **config_create.rs**: Creates a minimal s2n-tls configuration.
   - **config_configure.rs**: Configures an s2n-tls config with security policies and certificate key pairs.

2. **Cargo.toml**
   - The configuration file for building and running the regression tests using Cargo.

3. **run_harnesses.sh**
   - Script to run all harnesses, a specified harness, or a combination of harnesses with Valgrind and store annotated results.


## Prerequisites

Ensure you have the following installed:
- Rust (with Cargo)
- Valgrind (for crabgrind instrumentation)

## Running the Harnesses with Valgrind
To run the harnesses with Valgrind and store the annotated results, use the `run_harnesses.sh` script:

### Build s2n-tls
To build and ensure ensure the necessary files and dependencies are generated, follow these steps:


Run the 'generate.sh script to generate required files:

```
./generate.sh
```

Use cargo to build the project in release mode:

```
cargo build --release
```

### Run All Harnesses

To run all harnesses, execute the script without any arguments:

```
./run_harnesses.sh
```

### Run a Specific Harness

To run a specific harness, provide the harness name as an argument:

```
./run_harnesses.sh config_create
```

### Run Multiple Specified Harnesses

To run multiple specified harnesses, provide the harness names as arguments:

```
./run_harnesses.sh config_create config_configure
```

The script will build the harnesses, run each specified harness with Valgrind, store the unformatted output in the root directory and store the annotated output in the `perf_outputs` folder.

## Sample Output

Running the script will produce annotated cachegrind files which detail the instruction counts, how many instructions a particular file/function account for, and even the contribution of individual lines of code to the overall instruction count. For example, these are the first few lines of the output generated for 'config_create':

```
--------------------------------------------------------------------------------
-- Summary
--------------------------------------------------------------------------------
Ir__________________ 

282,156,931 (100.0%)  PROGRAM TOTALS

--------------------------------------------------------------------------------
-- File:function summary
--------------------------------------------------------------------------------
  Ir________________________  file:function

< 113,200,122 (40.1%, 40.1%)  /home/ubuntu/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.19.0/aws-lc/crypto/base64/base64.c:
   38,297,760 (13.6%)           base64_ascii_to_bin
   27,474,480  (9.7%)           constant_time_in_range_8
   21,230,280  (7.5%)           constant_time_lt_args_8
   14,949,848  (5.3%)           aws_lc_0_19_0_EVP_DecodeUpdate
   11,238,410  (4.0%)           base64_decode_quad

<  63,695,512 (22.6%, 62.7%)  /home/ubuntu/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.19.0/aws-lc/crypto/base64/../internal.h:
   17,483,760  (6.2%)           constant_time_msb_w
   17,483,760  (6.2%)           constant_time_is_zero_w
   14,986,080  (5.3%)           constant_time_eq_8
   13,737,240  (4.9%)           constant_time_eq_w

<  17,876,168  (6.3%, 69.0%)  /home/ubuntu/.cargo/registry/src/index.crates.io-6f17d22bba15001f/aws-lc-sys-0.19.0/aws-lc/crypto/bytestring/cbs.c:
    5,466,108  (1.9%)           cbs_get
    3,704,868  (1.3%)           aws_lc_0_19_0_CBS_get_u8
    2,199,934  (0.8%)           cbs_get_any_asn1_element
    1,316,592  (0.5%)           aws_lc_0_19_0_CBS_len
    1,062,264  (0.4%)           parse_asn1_tag
      864,690  (0.3%)           aws_lc_0_19_0_CBS_init
      765,468  (0.3%)           aws_lc_0_19_0_CBS_get_any_ber_asn1_element
      758,760  (0.3%)           aws_lc_0_19_0_CBS_get_bytes
      506,760  (0.2%)           aws_lc_0_19_0_CBS_skip
      399,990  (0.1%)           aws_lc_0_19_0_CBS_is_valid_asn1_oid

```

### Understanding the Output
The total instruction counts are listed at the top, and segmented by file:function beneath it. When comparing versions of s2n-tls (during PR workflow or otherwise) this can be useful to pinpoint the source of instruction count difference to inform you on how changes to the code impact performance. This [link](https://valgrind.org/docs/manual/cg-manual.html#cg-manual.running-cg_annotate:~:text=Information%20Source%20Code%20Documentation%20Contact%20How%20to%20Help%20Gallery,5.2.3.%C2%A0Running%20cg_annotate,-Before%20using%20cg_annotate) provides a more detailed description to fully understand the output file. 

## Test Details

### config_create.rs

Creates a minimal s2n-tls configuration and ensures it can be built successfully.

### config_configure.rs

Configures an s2n-tls configuration with a specified security policy and loads a certificate key pair. Ensures the configuration is valid and can be built.

