#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Run historical benchmarking by checking out old version of s2n-tls into target/
# Criterion JSON results get cached to target/historical-perf/[bench-group-name]/[version].json
# Results are then plotted, saved to images/historical-perf-[bench-name].svg
# All given arguments (ex. `--config aws-lc-config/s2n.toml` to use AWS-LC) are passed to Cargo

# immediately bail if any command fails
set -e

# suppress stdout and most cargo warnings
exec >/dev/null
export CARGO_TERM_QUIET=true
export RUSTFLAGS=-Awarnings

# go to bench directory
pushd "$(dirname "$0")"/../
bench_path="$(pwd)"

# delete past runs
rm -rf target/historical-perf

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
copied_bindings_path="$(pwd)"

# get list of tags sorted newest to oldest
sorted_tags="$(git tag -l | sort -rV)"

# last tag we want is v1.3.16, get line number of v1.3.16 in sorted_tags
line_num_last_tag=$(echo "$sorted_tags" | grep "v1.3.16" --line-number | head -n 1 | cut -d":" -f1)

# loop through all tags in order up to v1.3.16
for tag in $(echo "$sorted_tags" | head -$line_num_last_tag)
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
        cargo bench --no-default-features --no-fail-fast

        # cache criterion outputs from this bench into target/historical-perf
        for bench_group in $(ls target/criterion | grep -v "report")
        do
            mkdir -p target/historical-perf/$bench_group/
            cp target/criterion/$bench_group/s2n-tls/new/estimates.json target/historical-perf/$bench_group/$tag.json
        done
    ) || echo "failed, trying next tag"
    echo
done

# graph results
cd $bench_path
cargo run --release --no-default-features --features historical-perf --bin graph_perf

popd
