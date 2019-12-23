#!/bin/bash
# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
    echo "install_openssl_1_0_2_fips.sh build_dir install_dir os_name"
    exit 1
}

if [ "$#" -ne "3" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
OS_NAME=$3

if [ "$OS_NAME" == "linux" ]; then
    CONFIGURE="./config -d"
elif [ "$OS_NAME" == "osx" ]; then
    echo "WARNING: FIPS and MacOS is not officially supported. This build should only be used for local debugging."
    echo "See: http://openssl.6102.n7.nabble.com/Openssl-Fips-build-for-Mac-OSX-64-bit-td44716.html"
    CONFIGURE="./Configure darwin64-x86_64-cc"
else
    echo "Invalid platform! $OS_NAME"
    usage
fi

# Install the FIPS object module in accordance with OpenSSL FIPS 140-2 Security Policy Annex A.
#     https://www.openssl.org/docs/fips/SecurityPolicy-2.0.pdf
# This installation is not FIPS compliant as we do not own the build system architecture.
# It may only be used for testing purposes.
#
# There is no 'latest' download URL for the FIPS object modules
cd "$BUILD_DIR"
# Originally from: http://www.openssl.org/source/openssl-fips-2.0.13.tar.gz
curl --retry 3 https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2017-08-31_openssl-fips-2.0.13.tar.gz --output openssl-fips-2.0.13.tar.gz
gunzip -c openssl-fips-2.0.13.tar.gz | tar xf -
rm openssl-fips-2.0.13.tar.gz
cd openssl-fips-2.0.13
mkdir ../OpensslFipsModule
FIPSDIR="$(pwd)/../OpensslFipsModule"
export FIPSDIR
chmod +x ./Configure
$CONFIGURE
make
make install

cd "$BUILD_DIR"
curl --retry 3 -L https://github.com/openssl/openssl/archive/OpenSSL_1_0_2-stable.zip --output openssl-OpenSSL_1_0_2-stable.zip
unzip openssl-OpenSSL_1_0_2-stable.zip
cd openssl-OpenSSL_1_0_2-stable

FIPS_OPTIONS="fips --with-fipsdir=$FIPSDIR shared"

$CONFIGURE $FIPS_OPTIONS -g3 -fPIC no-libunbound no-gmp no-jpake no-krb5 no-md2 no-rc5 \
         no-rfc3779 no-sctp no-ssl-trace no-store no-zlib no-hw no-mdc2 no-seed no-idea \
         enable-ec_nistp_64_gcc_128 no-camellia no-bf no-ripemd no-dsa no-ssl2 no-capieng -DSSL_FORBID_ENULL \
         -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS --prefix="$INSTALL_DIR"

make depend
make
make install_sw

popd

exit 0

