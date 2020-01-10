#!/bin/bash
#
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

set -e

usage() {
    echo "install_gnutls.sh build_dir install_dir os_name"
    exit 1
}

if [ "$#" -ne "3" ]; then
    usage
fi

GNUTLS_BUILD_DIR=$1
GNUTLS_INSTALL_DIR=$2
OS_NAME=$3

# libgmp is needed for libnettle
if [ "$OS_NAME" == "linux" ]; then
    apt-get -qq install libgmp3-dev -y
elif [ "$OS_NAME" == "osx" ]; then
    # Installing an existing package is a "failure" in brew
    brew install gmp || true ;
else
    echo "Invalid platform! $OS_NAME"
    usage
fi

cd "$GNUTLS_BUILD_DIR"

# libnettle is a dependency of GnuTLS
# Originally from: https://ftp.gnu.org/gnu/nettle/nettle-3.3.tar.gz
curl --retry 3 https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2017-08-29_nettle-3.3.tar.gz --output nettle-3.3.tar.gz
tar -xzf nettle-3.3.tar.gz
cd nettle-3.3
./configure --prefix="$GNUTLS_INSTALL_DIR"/nettle
make
make install
cd ..

# Install GnuTLS
# Originally from: ftp://ftp.gnutls.org/gcrypt/gnutls/v3.5/gnutls-3.5.5.tar.xz
curl --retry 3 https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2017-08-29_gnutls-3.5.5.tar.xz --output gnutls-3.5.5.tar.xz
tar -xJf gnutls-3.5.5.tar.xz
cd gnutls-3.5.5
./configure LD_FLAGS="-R$GNUTLS_INSTALL_DIR/nettle/lib -L$GNUTLS_INSTALL_DIR/nettle/lib -lnettle -lhogweed" \
            NETTLE_LIBS="-R$GNUTLS_INSTALL_DIR/nettle/lib -L$GNUTLS_INSTALL_DIR/nettle/lib -lnettle" \
            NETTLE_CFLAGS="-I$GNUTLS_INSTALL_DIR/nettle/include" \
            HOGWEED_LIBS="-R$GNUTLS_INSTALL_DIR/nettle/lib -L$GNUTLS_INSTALL_DIR/nettle/lib -lhogweed" \
            HOGWEED_CFLAGS="-I$GNUTLS_INSTALL_DIR/nettle/include" \
            --without-p11-kit \
            --with-included-libtasn1 \
            --prefix="$GNUTLS_INSTALL_DIR"
make
make install
