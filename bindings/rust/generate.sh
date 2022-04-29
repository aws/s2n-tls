#/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -e

# cd into the script directory so it can be executed from anywhere
cd "$(dirname "${BASH_SOURCE[0]}")"

mkdir -p s2n-tls-sys/lib
mkdir -p s2n-tls-sys/lib/tests

# we copy the C sources into the `lib` directory so they get published in the
# actual crate artifact.
cp -r \
  ../../api \
  ../../crypto \
  ../../error \
  ../../pq-crypto \
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
cd generate && cargo run -- ../s2n-tls-sys && cd ..

# make sure everything builds and passes sanity checks
cd s2n-tls-sys \
  && cargo test \
  && cargo test --features pq \
  && cargo test --features quic \
  && cargo test --features internal \
  && cargo test --release \
  && cargo publish --dry-run --allow-dirty \
  && cargo publish --dry-run --allow-dirty --all-features \
  && cd ..

cd integration \
  && cargo run \
  && cd ..
