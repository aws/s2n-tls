#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# generates rust bindings with aws-lc
# if bench was built previously, use `cargo clean` to remove old s2n-tls build
# all arguments taken in are passed to `cargo bench`
# dependencies: Go (make sure it's on PATH!)

# aws-lc build directory: s2n-tls/libcrypto-build/
# aws-lc install directory: s2n-tls/libcrypto-root/

set -e

# go to repo directory from calling script anywhere
pushd "$(dirname "$0")/../../../"

# clean up past builds
repo_dir=`pwd`
rm -rf libcrypto-root
mkdir libcrypto-root
rm -rf libcrypto-build/aws-lc

# clone clean aws-lc
cd libcrypto-build/
git clone https://github.com/aws/aws-lc --depth=1
cd aws-lc

# build aws-lc to libcrypto-root
cmake -B build -DCMAKE_INSTALL_PREFIX=$repo_dir/libcrypto-root/ -DBUILD_TESTING=OFF -DBUILD_LIBSSL=OFF
cmake --build ./build -j $(nproc)
make -C build install

# build s2n-tls
cd $repo_dir
cmake . -Bbuild -DCMAKE_PREFIX_PATH=$repo_dir/libcrypto-root/ -DS2N_INTERN_LIBCRYPTO=ON -DBUILD_TESTING=OFF
cmake --build ./build -j $(nproc)

# tell linker where s2n-tls was built
export S2N_TLS_LIB_DIR=$repo_dir/build/lib
export S2N_TLS_INCLUDE_DIR=$repo_dir/api
export LD_LIBRARY_PATH=$S2N_TLS_LIB_DIR:$LD_LIBRARY_PATH

# generate bindings with aws-lc
cd bindings/rust
cargo clean
./generate.sh

# bench everything (including memory)
cd bench
cargo clean
./memory-bench.sh
cargo bench $@

popd
