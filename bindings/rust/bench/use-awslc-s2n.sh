#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# sets bench crate to use aws-lc with s2n-tls
# all artifacts are in target/aws-lc and target/s2n-tls-build

set -e

# go to bench directory
pushd "$(dirname "$0")" > /dev/null
bench_dir="$(pwd)"

s2n_tls_build_dir="$bench_dir"/target/s2n-tls-build
aws_lc_dir="$bench_dir"/target/aws-lc

# go to repo directory
pushd "$(dirname "$0")/../../../" > /dev/null
repo_dir="$(pwd)"
popd > /dev/null

# if libs2n not found, build it
if [ ! -e "$s2n_tls_build_dir"/lib/libs2n.a ]
then
    # if aws-lc not found, build it
    if [ ! -e "$aws_lc_dir"/install/lib/libcrypto.a ]
    then
        # clone fresh aws-lc
        cd "$bench_dir"/target
        rm -rf aws-lc
        git clone --depth=1 https://github.com/aws/aws-lc
        cd aws-lc

        # build and install aws-lc
        cmake -B build -DCMAKE_INSTALL_PREFIX="$aws_lc_dir"/install -DBUILD_TESTING=OFF -DBUILD_LIBSSL=OFF
        cmake --build ./build -j $(nproc)
        make -C build install
    else
        echo "using libcrypto.a at target/aws-lc/install/lib"
    fi

    # clean up directories
    rm -rf "$s2n_tls_build_dir"
    mkdir -p "$s2n_tls_build_dir"

    # build and install s2n-tls
    cd "$repo_dir"
    cmake . -B "$s2n_tls_build_dir" -DCMAKE_PREFIX_PATH="$aws_lc_dir"/install -DS2N_INTERN_LIBCRYPTO=ON -DBUILD_TESTING=OFF
    cmake --build "$s2n_tls_build_dir" -j $(nproc)
else
    echo "using libs2n.a at target/s2n-tls-build/lib"
fi

# tell s2n-tls-sys crate where s2n-tls was built with .cargo/config.toml
cd "$repo_dir"/bindings/rust/bench
mkdir -p .cargo
# if .cargo/config.toml doesn't already have an [env] header, add it
if [[ ! -f .cargo/config.toml || "$(cat .cargo/config.toml)" != *"[env]"* ]]; then
echo "[env]
S2N_TLS_LIB_DIR = \"$s2n_tls_build_dir/lib\"
LD_LIBRARY_PATH = \"$s2n_tls_build_dir/lib\"" >> .cargo/config.toml
fi

# force rebuild of s2n-tls-sys and benches
rm -rf ../target/release target/release

popd > /dev/null
