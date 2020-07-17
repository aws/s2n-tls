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
    echo "install_oqs_openssl_1_1_1.sh build_dir install_dir travis_platform"
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

# As of 2020-07-08, libOQS has migrated to Picnic-v3, but open-quantum-safe/openssl is still using the removed v2 symbols (OQS_SIG_alg_picnic2_L1_FS)
# Pin to commit before Picnic-v3 was merged into liboqs so that both libraries are compatible with each other.
git checkout 1b9aecc65672f86487018ee6f9786216578e4e29

mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=${BUILD_DIR}/openssl/oqs ..
ninja
ninja install


# Complete the OpenSSL Build
cd "$BUILD_DIR"/openssl

# Pin to working OQS OpenSSL commit so that a future migration to Picnic-V3 won't break CI.
git checkout 97242266b4402d21724c62f2005b51feb977ceb1

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