#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# sets bench crate to use aws-lc-rs instead of ring for rustls

set -e

# go to bench directory
pushd "$(dirname "$0")" > /dev/null
bench_dir="$(pwd)"

# clone rustls to bench/target/rustls and checkout compatible version
rm -rf target/rustls
git clone https://github.com/rustls/rustls target/rustls
cd target/rustls
git checkout 'v/0.21.5'

# go to dir with rustls crate
cd rustls
rustls_dir="$(pwd)"

# change rustls to use aws-lc-rs
sed -i 's|ring = .*|ring = { package = "aws-lc-rs" }|' Cargo.toml

# tell Cargo to use custom rustls
cd $bench_dir
mkdir -p .cargo
# if .cargo/config.toml doesn't already have an [patch.crates-io] header, add it
if [[ ! -f .cargo/config.toml || "$(cat .cargo/config.toml)" != *"[patch.crates-io]"* ]]; then
echo "[patch.crates-io]
rustls = { path = \"$rustls_dir\" }" >> .cargo/config.toml
fi

popd > /dev/null
