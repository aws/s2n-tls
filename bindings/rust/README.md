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

Alternatively, rust bindings can be generated using pre-built libs2n by first compiling libs2n, and then running the `generate.sh` script:
```
cmake . -Bbuild -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=off
cmake --build build -- -j $(nproc)

export S2N_TLS_LIB_DIR=`pwd`/build/lib
export S2N_TLS_INCLUDE_DIR=`pwd`/api
export LD_LIBRARY_PATH=$S2N_TLS_LIB_DIR:$LD_LIBRARY_PATH

cd bindings/rust/
./generate.sh
```
This method is useful if you want the bindings to be built with a non-default libcrypto. Currently, the default libcrypto when generating rust bindings is `aws-lc`.

## Minimum Supported Rust Version (MSRV)

`s2n-tls` will maintain a rolling MSRV (minimum supported rust version) policy of at least 6 months. The current s2n-quic version is not guaranteed to build on Rust versions earlier than the MSRV.

The current MSRV is [1.63.0][msrv-url].

