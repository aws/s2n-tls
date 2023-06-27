#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# immediately bail if any command fails
set -e

# go to directory script is located in
bench_path=`pwd`/`dirname "$0"`/../
pushd $bench_path

# clone copy of repo to checkout old version from
mkdir -p target
cd target
rm -rf s2n-tls
git clone https://github.com/aws/s2n-tls
cd s2n-tls/bindings/rust/
rm -rf bench
mkdir bench
cd bench

# loop through all tags in order, newest to oldest
# working directory is bench folder inside repo
for tag in `git tag -l | sort -rV`
do
    # for each tag, build (generate bindings) and bench
    echo $tag
    git checkout -f $tag
    ../generate.sh
    cp -r $bench_path/{benches/,certs/,historical-perf/,src/,Cargo.toml,rust-toolchain} ./
    cp $bench_path/../Cargo.toml ../Cargo.toml
    cargo bench
    cargo run --release --bin parse_criterion $tag $bench_path/historical-perf/perf.csv
done

popd
