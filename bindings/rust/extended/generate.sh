#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -xe

# cd into the script directory so it can be executed from anywhere
pushd "$(dirname "${BASH_SOURCE[0]}")"

# Helper function to check if the rust bindings is running on Windows
is_windows() {
    local os
    os="$(uname -s)"
    if [[ "$os" == MINGW* || "$os" == MSYS* || "$os" == CYGWIN* ]]; then
        true
    else
        false
    fi
}

# delete the existing copy in case we have extra files
rm -rf s2n-tls-sys/lib
mkdir -p s2n-tls-sys/lib
mkdir -p s2n-tls-sys/lib/tests
mkdir -p s2n-tls-sys/src/features

# we copy the C sources into the `lib` directory so they get published in the
# actual crate artifact.
cp -r \
  ../../../api \
  ../../../crypto \
  ../../../error \
  ../../../stuffer \
  ../../../tls \
  ../../../utils \
  s2n-tls-sys/lib/

cp -r \
  ../../../tests/features \
  s2n-tls-sys/lib/tests/

cp -r \
  ../../../CMakeLists.txt \
  ../../../cmake \
  s2n-tls-sys/lib/

# generate the bindings modules from the copied sources
pushd generate
# Behavior change from https://github.com/rust-lang/rustup/pull/3985
rustc --version || rustup toolchain install
rustup component add rustfmt
cargo run -- ../s2n-tls-sys
popd

if [ "$1" == "--skip-tests" ]; then
    echo "skipping tests"
    exit;
fi;

# make sure everything builds and passes sanity checks
pushd s2n-tls-sys
cargo test
cargo test --release
cargo publish --dry-run --allow-dirty
if is_windows; then
    # `fips` is the one feature that can't build on Windows/MinGW, since aws-lc-fips-sys can't be built on MSYS2 MinGW.
    # Test every other feature instead of `--all-features`.
    # The list is read from the manifest, so newly added features are covered automatically.
    windows_features=$(cargo metadata --no-deps --format-version 1 \
        | jq -r '.packages[] | select(.name == "s2n-tls-sys").features | keys - ["default", "fips"] | join(",")')
    cargo test --features "$windows_features"
    cargo publish --dry-run --allow-dirty --features "$windows_features"
else
    cargo test --all-features
    cargo publish --dry-run --allow-dirty --all-features
fi
popd

pushd ../standard/integration
rustc --version || rustup toolchain install
cargo run
popd

popd
