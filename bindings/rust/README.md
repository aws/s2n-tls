# s2n-tls Rust Bindings

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
$ ./bindings/rust/extended/generate.sh
```

This script generates the low-level bindings in the crate `s2n-tls-sys`, which is used by the `s2n-tls` crate to provide higher-level bindings.
See [s2n-tls-sys](https://github.com/aws/s2n-tls/blob/main/bindings/rust/s2n-tls-sys/README.md) for more information on `s2n-tls-sys` crate.

## Windows

The rust bindings are supported on Windows through the [MSYS2](https://www.msys2.org/) environment with a MinGW toolchain. Use a GNU Rust target rather than an MSVC target: `x86_64-pc-windows-gnu` for the `UCRT64`/`MINGW64` environments, or `x86_64-pc-windows-gnullvm` for the `CLANG64` environment. The MSVC toolchain (`*-pc-windows-msvc`) is not supported.

On Windows, AWS-LC is the only supported libcrypto. The bindings link against AWS-LC through the `aws-lc-rs` crate (which builds AWS-LC from source), so no separate libcrypto needs to be installed.

From a MinGW shell, install the toolchain and dependencies (the package prefix depends on the environment, e.g. `mingw-w64-ucrt-x86_64` for `UCRT64`), then generate the bindings as usual:

```bash
# example for the UCRT64 environment
pacman -S --needed \
    mingw-w64-ucrt-x86_64-clang \
    mingw-w64-ucrt-x86_64-clang-libs \
    mingw-w64-ucrt-x86_64-cmake \
    mingw-w64-ucrt-x86_64-ninja \
    mingw-w64-ucrt-x86_64-rustup \
    make

rustup default stable-x86_64-pc-windows-gnu
./bindings/rust/extended/generate.sh
```

## Minimum Supported Rust Version (MSRV)

There are two rust bindings workspaces that have different MSRV policies. Crates in `standard` maintain a rolling MSRV policy of at least 6 months. Crates in `extended` maintain an older MSRV for increased support.

### Extended

Crates in the `extended` workspace currently support an "extended" MSRV of [1.77.0](https://releases.rs/docs/1.77.0/). This is a temporary state. Customers must not rely on `s2n-tls` crates maintaining this level of stability. We expect to revert back to the mentioned standard policy shortly.

### Standard

We will maintain a rolling MSRV (minimum supported rust version) policy of at least 6 months. The current s2n-tls version is not guaranteed to build on Rust versions earlier than the MSRV.

