#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Benches memory usage for all possible configurations and generate plots in images/
# All given arguments (ex. `--config aws-lc-config/s2n.toml` to use AWS-LC) are passed to Cargo

set -e

pushd "$(dirname "$0")"/.. > /dev/null

cargo build --release --features memory --bin memory --bin graph_memory "$@"

# iterate through all possible options
for reuse_config in false true
do
    for shrink_buffers in false true
    do
        for bench_target in client server pair
        do
            valgrind --tool=massif --depth=1 --massif-out-file="target/memory/massif.out" --time-unit=ms target/release/memory $bench_target --reuse-config $reuse_config --shrink-buffers $shrink_buffers
            rm target/memory/massif.out
        done
    done
done

cargo run --release --features memory --bin graph_memory "$@"

popd > /dev/null
