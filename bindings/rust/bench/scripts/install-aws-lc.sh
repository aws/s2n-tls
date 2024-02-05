#!/usr/bin/env bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Usage: ./install-aws-lc.sh
# Sets up bench crate to use aws-lc for either s2n-tls or rustls if desired

# To run benches with aws-lc, use any cargo command with:
# --config aws-lc-config/s2n.toml
# --config aws-lc-config/rustls.toml
# or both

# How Rustls with aws-lc-rs works:
# Clones aws-lc-rs, changes its name to ring with a compatible version number, and
# patches it into Rustls

# How s2n-tls with aws-lc works:
# Builds s2n-tls static lib with AWS-LC interned, required to avoid symbol collisions with OpenSSL
# Checks for libs2n.a at target/s2n-tls-build/lib/libs2n.a
# Checks for libcrypto.a at target/aws-lc/install/lib/libcrypto.a

set -e 

# go to bench directory
pushd "$(dirname "$0")"/.. > /dev/null
bench_dir="$(pwd)"



# ----- rustls -----

# clone aws-lc-rs to target
rm -rf target/aws-lc-rs
git clone https://github.com/aws/aws-lc-rs target/aws-lc-rs
cd target/aws-lc-rs/aws-lc-rs
git submodule init
git submodule update

# change aws-lc-rs to look like API compatible ring (name and version)
# first get the version of ring that Cargo expects with `cargo tree`
pushd "$bench_dir" > /dev/null
version="$(cargo tree -p ring | head -n 1 | sed 's|ring v||')"
popd > /dev/null
# next change first occurrence of 'name = .*' and 'version = .*' in Cargo.toml
# to be 'name = "ring"' and 'version = "[curr_version]"'
sed -i "1,/name = .*/{s|name = .*|name = \"ring\"|} ; 1,/version = .*/{s|version = .*|version = \"$version\"|}" Cargo.toml



# ----- s2n-tls -----

# put all build artifacts in target
s2n_tls_build_dir="$bench_dir"/target/s2n-tls-build
aws_lc_dir="$bench_dir"/target/aws-lc

# go to repo directory
cd "$bench_dir"/../../../
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
        cmake -B build -DCMAKE_INSTALL_PREFIX="$aws_lc_dir"/install -DBUILD_TESTING=OFF -DBUILD_LIBSSL=OFF -DCMAKE_BUILD_TYPE=Release
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
    cmake . -B "$s2n_tls_build_dir" -DCMAKE_PREFIX_PATH="$aws_lc_dir"/install -DS2N_INTERN_LIBCRYPTO=ON -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release
    cmake --build "$s2n_tls_build_dir" -j $(nproc)
else
    echo "using libs2n.a at target/s2n-tls-build/lib"
fi

# force rebuild of s2n-tls-sys and benches
rm -rf ../target/release target/release



popd > /dev/null
