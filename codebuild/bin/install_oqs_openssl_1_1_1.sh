#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

set -ex

usage() {
    echo "install_oqs_openssl_1_1_1.sh build_dir install_dir platform"
    exit 1
}

if [ "$#" -ne "3" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
PLATFORM=$3

cd "$BUILD_DIR"

# Download OQS OpenSSL Source code
git clone --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git


# Download and Build OQS library, and copy "lib" and "include" artifacts into OQS OpenSSL directory
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Use commit that supports Kyber round 3; hybrid draft spec version 5
git checkout cf6d8a059e446d24e2af06949d83605ae0f4f414

mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=${BUILD_DIR}/openssl/oqs ..
ninja
ninja install


# Complete the OpenSSL Build
cd "$BUILD_DIR"/openssl

# Pin to OQS-OpenSSL commit that is compatible with Kyber round 3; hybrid draft spec version 5 LibOQS implementation
git checkout 613d1bea7afa23dc11f340e75990cb47d77711e9

if [ "$PLATFORM" == "linux" ]; then
    CONFIGURE="./config -d"
elif [ "$PLATFORM" == "osx" ]; then
    CONFIGURE="./Configure darwin64-x86_64-cc"
else
    echo "Invalid platform! $PLATFORM"
    usage
fi

# Use g3 to get debug symbols in libcrypto to chase memory leaks
$CONFIGURE -g3 -fPIC              \
         no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib     \
         no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia \
         no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng                  \
         -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
         --prefix="$INSTALL_DIR"

make depend
make -j
make install_sw

exit 0