#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Generate flamegraphs for handshake and throughput performance
# Flamegraphs get stored as images/flamegraph/[bench-name]/[lib-name].svg
# All given arguments (ex. `--config aws-lc-config/s2n.toml` to use AWS-LC) are passed to Cargo

set -e

# go to bench directory
pushd "$(dirname "$0")"/.. > /dev/null

# generate flamegraphs
# cargo bench --bench handshake --bench throughput "$@" -- --profile-time 5

# copy flamegraphs to correct path
for path in $(find target/criterion -name flamegraph.svg)
do
    # strip "target/criterion/" and "/profile/flamegraph" from the path
    new_path=images/flamegraph/"$(echo "$path" | sed 's|target\/criterion\/|| ; s|\/profile\/flamegraph||')"
    mkdir -p "$(dirname $new_path)"
    cp "$path" "$new_path"
done

popd > /dev/null
