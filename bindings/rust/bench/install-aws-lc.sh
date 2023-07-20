#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Sets up bench crate to use aws-lc for either s2n-tls or rustls if desired
# To run with aws-lc, use any cargo command with:
# --config aws-lc-config/s2n.toml
# --config aws-lc-config/rustls.toml
# or both

set -e 

# go to bench directory
pushd "$(dirname "$0")" > /dev/null
bench_dir="$(pwd)"



# ----- rustls -----

# clone rustls to bench/target/rustls and checkout compatible version
rm -rf target/rustls
git clone https://github.com/rustls/rustls target/rustls
cd target/rustls
git checkout 'v/0.21.5'

# go to dir with rustls crate
cd rustls
rustls_dir="$(pwd)"

# change rustls to use aws-lc-rs
sed -i 's|ring = .*|ring = { package = "aws-lc-rs" }|' Cargo.toml



# ----- s2n-tls -----

# put all build artifacts in target
s2n_tls_build_dir="$bench_dir"/target/s2n-tls-build
aws_lc_dir="$bench_dir"/target/aws-lc

# go to repo directory
cd "$bench_dir"/../../../ > /dev/null
repo_dir="$(pwd)"

# if libs2n not found, build it
if [ ! -e "$s2n_tls_build_dir"/lib/libs2n.a ]
then
    # if aws-lc not found, build it
    if [ ! -e "$aws_lc_dir"/install/lib/libcrypto.a ]
    then
        # clone fresh aws-lc
        cd "$bench_dir"
        rm -rf target/aws-lc
        git clone --depth=1 https://github.com/aws/aws-lc target/aws-lc
        cd target/aws-lc

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

# force rebuild of s2n-tls-sys and benches
rm -rf ../target/release target/release



popd > /dev/null
