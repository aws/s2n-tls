# Regression Testing for s2n-tls

This folder contains regression tests and benchmarking tools for the `s2n-tls` library. The tests focus on various aspects of TLS connections, including handshakes and session resumptions.

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

### Make the Script Executable

Make the `run_harnesses.sh` script executable:

```
chmod +x run_harnesses.sh
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

## Test Details

### config_create.rs

Creates a minimal s2n-tls configuration and ensures it can be built successfully.

### config_configure.rs

Configures an s2n-tls configuration with a specified security policy and loads a certificate key pair. Ensures the configuration is valid and can be built.

## Contributing to s2n-tls

If you are interested in contributing to s2n-tls, please see our [development guide](https://github.com/aws/s2n-tls/blob/main/docs/DEVELOPMENT-GUIDE.md).

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.
