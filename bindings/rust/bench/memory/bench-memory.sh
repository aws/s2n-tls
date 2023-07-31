#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Use Valgrind and Massif to heap profile the memory taken by different TLS libraries
# Uses Valgrind monitor commands to take snapshots of heap size while making connections

# Benches memory usage for all possible configurations and generate plots in images/

set -e

pushd "$(dirname "$0")"/.. > /dev/null

cargo build --release --bin memory "$@"

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

cargo run --release --bin graph_memory "$@"

popd > /dev/null
