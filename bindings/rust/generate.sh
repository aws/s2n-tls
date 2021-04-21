#/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# cd into the script directory so it can be executed from anywhere
cd "$(dirname "${BASH_SOURCE[0]}")"

mkdir -p s2n-tls-sys/lib

# we copy the C sources into the `lib` directory so they get published in the
# actual crate artifact.
cp -r \
  --update \
  ../../api \
  ../../crypto \
  ../../error \
  ../../pq-crypto \
  ../../stuffer \
  ../../tls \
  ../../utils \
  s2n-tls-sys/lib/

# generate the bindings modules from the copied sources
cd generate && cargo run -- ../s2n-tls-sys && cd ..

# make sure everything builds and passes sanity checks
cd s2n-tls-sys \
  && cargo test \
  && cargo test --release \
  && cargo test --features quic \
  && cd ..
