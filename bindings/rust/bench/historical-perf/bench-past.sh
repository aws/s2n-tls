#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# suppress stdout
exec >/dev/null
export CARGO_TERM_QUIET=true
export RUSTFLAGS=-Awarnings

# immediately bail if any command fails
set -e

# go to directory script is located in
bench_path=`pwd`/`dirname "$0"`/../
pushd $bench_path

# clone copy of repo to checkout old version from
echo "cloning repo" >&2
mkdir -p target
cd target
rm -rf s2n-tls
git clone --quiet https://github.com/aws/s2n-tls
cd s2n-tls/bindings/rust/
copied_bindings_path=`pwd`

# last tag we want is v1.3.16, get all tags up to there
# this gets the line number of the the last tag we want
line_num_last_tag=`git tag -l | sort -rV | grep "v1.3.16" --line-number | head -n 1 | cut -d":" -f1`

# loop through all tags in order, newest to oldest
# working directory is bench folder inside repo
for tag in `git tag -l | sort -rV | head -$line_num_last_tag`
do
    (
        cd $copied_bindings_path

        # checkout tag and copy over benching code
        echo "checkout out tag $tag" >&2
        git checkout -f $tag --quiet
        rm -rf bench && mkdir bench && cd bench
        mkdir -p benches/ certs/ historical-perf/ src/ 
        cp -r $bench_path/{benches/,certs/,historical-perf/,src/,Cargo.toml,rust-toolchain,use-awslc.sh} ./
        cp $bench_path/../Cargo.toml ../Cargo.toml

        echo "generating rust bindings" >&2
        #./use-awslc.sh
        ../generate.sh || exit 3

        echo "running cargo bench" >&2
        cargo bench --features "s2n-only"
        cargo run --release --bin parse_criterion $tag $bench_path/historical-perf/perf.csv
    ) || echo "failed, trying next tag"
done

popd
