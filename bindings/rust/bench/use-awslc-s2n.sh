#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# sets bench crate to use aws-lc with s2n-tls

set -e

# go to bench directory
pushd "$(dirname "$0")" > /dev/null
bench_dir="$(pwd)"

aws_lc_build_dir="$bench_dir"/target/aws-lc-build
aws_lc_install_dir="$bench_dir"/target/aws-lc-install

# go to repo directory
pushd "$(dirname "$0")/../../../" > /dev/null
repo_dir="$(pwd)"
popd > /dev/null

# if libs2n not found, build it
if [ ! -e "$repo_dir"/build/lib/libs2n.a ]
then
    # if aws-lc not found, build it
    if [ ! -e "$aws_lc_install_dir"/lib/libcrypto.a ]
    then
        # clean up directories
        rm -rf "$aws_lc_build_dir" "$aws_lc_install_dir"
        mkdir -p "$aws_lc_build_dir" "$aws_lc_install_dir"

        # clone aws-lc
        cd "$aws_lc_build_dir"
        git clone --depth=1 https://github.com/aws/aws-lc
        cd aws-lc

        # build aws-lc to libcrypto-root
        cmake -B build -DCMAKE_INSTALL_PREFIX="$aws_lc_install_dir" -DBUILD_TESTING=OFF -DBUILD_LIBSSL=OFF
        cmake --build ./build -j $(nproc)
        make -C build install
    else
        echo "using libcrypto.a at libcrypto-root/lib/"
    fi

    # build s2n-tls to s2n-tls/build
    cd $repo_dir
    cmake . -Bbuild -DCMAKE_PREFIX_PATH="$aws_lc_install_dir" -DS2N_INTERN_LIBCRYPTO=ON -DBUILD_TESTING=OFF
    cmake --build ./build -j $(nproc)
else
    echo "using libs2n.a at build/lib/"
fi

# tell s2n-tls-sys crate where s2n-tls was built with .cargo/config.toml
cd bindings/rust/bench
mkdir -p .cargo
# if .cargo/config.toml doesn't already have an [env] header, add it
if [[ ! -f .cargo/config.toml || "$(cat .cargo/config.toml)" != *"[env]"* ]]; then
echo "[env]
S2N_TLS_LIB_DIR = \"$repo_dir/build/lib\"
LD_LIBRARY_PATH = \"$repo_dir/build/lib\"" >> .cargo/config.toml
fi

# force rebuild of s2n-tls-sys and benches
rm -rf ../target/release target/release

popd > /dev/null
