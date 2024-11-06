# s2n-tls rust bindings

**NOTICE: These bindings are currently subject to change and should not be used without the expectation
of future breakage.**

## Installation

In order to generate rust bindings for s2n-tls, you need to have the following installed:

* Rust - this can be easily installed with [rustup](https://rustup.rs/)
* libclang - this is usually installed through your system's package manager
* libssl-dev
* pkg-config

## Usage

Generating rust bindings can be accomplished by running the `generate.sh` script:

```
$ ./bindings/rust/generate.sh
```

Our Rust bindings support using pre-built libs2n by using the [s2n-tls-sys crate](https://crates.io/crates/s2n-tls-sys) and following the next steps below:

1. Compile your preferred configuration of s2n-tls. 

You may choose to link against a specific libcrypto at this step. For more information, see [Building with a specific libcrypto](https://github.com/aws/s2n-tls/blob/main/docs/BUILD.md#building-with-a-specific-libcrypto)
```
cmake . -Bbuild -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=off
cmake --build build -- -j $(nproc)
```

2. CD into your rust project and set environment variables to libs2n library sources. 

This tells the bindings to link to pre-built libs2n when running the build script for s2n-tls-sys
```
export S2N_TLS_LIB_DIR=<PATH_TO_ROOT_OF_S2N_TLS>/build/lib
export S2N_TLS_INCLUDE_DIR=<PATH_TO_ROOT_OF_S2N_TLS>/api
export LD_LIBRARY_PATH=$S2N_TLS_LIB_DIR:$LD_LIBRARY_PATH
```

3. Build your project. This triggers the build script for s2n-tls-sys

```
cargo build
```

This method is useful if you want the bindings to be built with a non-default libcrypto. Currently, the default libcrypto when generating rust bindings is `aws-lc`.

## Minimum Supported Rust Version (MSRV)

`s2n-tls` will maintain a rolling MSRV (minimum supported rust version) policy of at least 6 months. The current s2n-quic version is not guaranteed to build on Rust versions earlier than the MSRV.

The current MSRV is [1.63.0][msrv-url].

