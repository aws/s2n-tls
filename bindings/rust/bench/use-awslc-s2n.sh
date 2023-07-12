#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# sets bench crate to use aws-lc with s2n-tls
# aws-lc build directory: s2n-tls/libcrypto-build/
# aws-lc install directory: s2n-tls/libcrypto-root/

set -e

# go to repo directory
pushd "$(dirname "$0")/../../../" > /dev/null
repo_dir="$(pwd)"

# if libs2n not found, build it
if [ ! -e build/lib/libs2n.a ]
then
    # if aws-lc not found, build it
    if [ ! -e libcrypto-root/lib/libcrypto.a ]
    then
        # clean up directories
        rm -rf libcrypto-root libcrypto-build/aws-lc
        mkdir libcrypto-root

        # clone aws-lc
        cd libcrypto-build/
        git clone --depth=1 https://github.com/aws/aws-lc
        cd aws-lc

        # build aws-lc to libcrypto-root
        cmake -B build -DCMAKE_INSTALL_PREFIX=$repo_dir/libcrypto-root/ -DBUILD_TESTING=OFF -DBUILD_LIBSSL=OFF
        cmake --build ./build -j $(nproc)
        make -C build install
    else
        echo "using libcrypto.a at libcrypto-root/lib/"
    fi

    # build s2n-tls
    cd $repo_dir
    cmake . -Bbuild -DCMAKE_PREFIX_PATH=$repo_dir/libcrypto-root/ -DS2N_INTERN_LIBCRYPTO=ON -DBUILD_TESTING=OFF
    cmake --build ./build -j $(nproc)
else
    echo "using libs2n.a at build/lib/"
fi

# tell s2n-tls-sys crate where s2n-tls was built with .cargo/config.toml
cd bindings/rust/bench
mkdir -p .cargo
echo "[env]
S2N_TLS_LIB_DIR = \"$repo_dir/build/lib\"
LD_LIBRARY_PATH = \"$repo_dir/build/lib\"" >> .cargo/config.toml

# force rebuild of s2n-tls-sys and benches
rm -rf ../target/release target/release

popd > /dev/null
