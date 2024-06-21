#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -xe

# cd into the script directory so it can be executed from anywhere
pushd "$(dirname "${BASH_SOURCE[0]}")"

# delete the existing copy in case we have extra files
rm -rf s2n-tls-sys/lib
mkdir -p s2n-tls-sys/lib
mkdir -p s2n-tls-sys/lib/tests
mkdir -p s2n-tls-sys/src/features

# we copy the C sources into the `lib` directory so they get published in the
# actual crate artifact.
cp -r \
  ../../api \
  ../../crypto \
  ../../error \
  ../../stuffer \
  ../../tls \
  ../../utils \
  s2n-tls-sys/lib/

cp -r \
  ../../tests/features \
  s2n-tls-sys/lib/tests/

cp -r \
  ../../CMakeLists.txt \
  ../../cmake \
  s2n-tls-sys/lib/

# generate the bindings modules from the copied sources
pushd generate
cargo run -- ../s2n-tls-sys
popd

if [ "$1" == "--skip-tests" ]; then
    echo "skipping tests"
    exit;
fi;

# make sure everything builds and passes sanity checks
pushd s2n-tls-sys
cargo test
cargo test --all-features
cargo test --release
cargo publish --dry-run --allow-dirty
cargo publish --dry-run --allow-dirty --all-features
popd

pushd integration
cargo run
popd

popd
