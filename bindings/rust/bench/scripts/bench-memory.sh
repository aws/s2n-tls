#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Use Valgrind and Massif to heap profile the memory taken by different TLS libraries
# Uses Valgrind monitor commands to take snapshots of heap size while making connections
# All given arguments (ex. `--config aws-lc-config/s2n.toml` to use AWS-LC) are passed to Cargo

# Snapshots get stored in target/memory/[library-name]/ as [number].snapshot

set -e

pushd "$(dirname "$0")"/.. > /dev/null

cargo build --release --bin memory --bin graph_memory "$@"

valgrind --tool=massif --depth=1 --massif-out-file="target/memory/massif.out" --time-unit=ms target/release/memory 
rm target/memory/massif.out

cargo run --release --bin graph_memory "$@"

popd > /dev/null
