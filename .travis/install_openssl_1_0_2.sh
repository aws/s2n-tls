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
pushd "$(pwd)"

usage() {
    echo "install_openssl_1_0_2.sh build_dir install_dir travis_platform"
    exit 1
}

if [ "$#" -ne "3" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
PLATFORM=$3

cd "$BUILD_DIR"
curl --retry 3 -L https://github.com/openssl/openssl/archive/OpenSSL_1_0_2-stable.zip --output openssl-OpenSSL_1_0_2-stable.zip
unzip openssl-OpenSSL_1_0_2-stable.zip
cd openssl-OpenSSL_1_0_2-stable

if [ "$PLATFORM" == "linux" ]; then
    CONFIGURE="./config -d"
elif [ "$PLATFORM" == "osx" ]; then
    CONFIGURE="./Configure darwin64-x86_64-cc"
else
    echo "Invalid platform! $PLATFORM"
    usage
fi

$CONFIGURE -g3 -fPIC no-libunbound no-gmp no-jpake no-krb5 no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace \
         no-store no-zlib no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia no-bf no-ripemd \
         no-dsa no-ssl2 no-capieng -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS \
         --prefix="$INSTALL_DIR"

make depend
make
make install_sw

popd

exit 0

