#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# suppress stdout
exec >/dev/null
export CARGO_TERM_QUIET=true
export RUSTFLAGS=-Awarnings

# immediately bail if any command fails
set -e

# go to s2n-tls/bindings/rust/bench/
bench_path=`pwd`/`dirname "$0"`/../
pushd $bench_path

# make Cargo.toml point s2n-tls to the cloned old version
sed -i "s|s2n-tls = .*|s2n-tls = { path = \"target/s2n-tls/bindings/rust/s2n-tls\" }|" Cargo.toml 

# ensure Cargo.toml gets changed back on exit; retains original exit status
trap "{ status=$?; sed -i 's|s2n-tls = .*|s2n-tls = { path = \"../s2n-tls\" }|' $bench_path/Cargo.toml; exit $status; }" EXIT

# clone copy of repo to target/s2n-tls
echo "cloning repo" >&2
mkdir -p target
cd target
rm -rf s2n-tls
git clone --quiet https://github.com/aws/s2n-tls
cd s2n-tls/bindings/rust/
copied_bindings_path=`pwd`

# last tag we want is v1.3.16, get all tags from then
# `git tag -l | sort -rV` gets list of sorted tags newest to oldest

# get the line number of v1.3.16
line_num_last_tag=`git tag -l | sort -rV | grep "v1.3.16" --line-number | head -n 1 | cut -d":" -f1`

# loop through all tags in order up to v1.3.16
for tag in `git tag -l | sort -rV | head -$line_num_last_tag`
do
    (
        # go to s2n-tls/bindings/rust/ inside copied repo
        cd $copied_bindings_path

        echo "checkout tag $tag" >&2
        git checkout $tag --quiet

        echo "generating rust bindings" >&2
        # if generate.sh fails, exit out of block
        ./generate.sh || exit 1

        echo "running cargo bench and saving results" >&2
        cd $bench_path
        rm -rf target/criterion
        cargo bench --features "s2n-only" --no-fail-fast
        cargo run --release --bin parse_criterion $tag historical-perf/perf.csv
    ) || echo "failed, trying next tag"
    echo
done

# graph results
cargo run --release --bin graph_perf

popd
