#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Use Valgrind and Massif to heap profile the memory taken by different TLS libraries
# Uses Valgrind monitor commands to take snapshots of heap size while making connections

# Snapshots get stored in target memory/[library-name]/ as [number].snapshot

set -e

pushd "$(dirname "$0")"/.. > /dev/null

cargo build --release --bin memory

for reuse_config in false true
do
    for shrink_buffers in false true
    do
        for library in s2n-tls rustls openssl
        do
            for bench_target in client server pair
            do
                valgrind --tool=massif --depth=1 --massif-out-file="target/memory/massif.out" --time-unit=ms target/release/memory $library $bench_target --reuse-config $reuse_config --shrink-buffers $shrink_buffers
                rm target/memory/massif.out
            done
        done
        unset name

    done
done

cargo run --release --bin graph_memory

popd > /dev/null
