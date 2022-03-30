#!/bin/bash
#
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

set -e
source codebuild/bin/s2n_setup_env.sh

usage() {
    echo "install_gnutls37.sh build_dir install_dir os_name"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

GNUTLS_BUILD_DIR=$1
GNUTLS_INSTALL_DIR=$2

source codebuild/bin/jobs.sh

# libgmp is needed for libnettle
case "$DISTRO" in
  "ubuntu")
    sudo apt-get -qq install libgmp3-dev -y
    ;;
  "amazon linux")
    sudo yum install -y gmp-devel
    ;;
"darwin" )
    # Installing an existing package is a "failure" in brew
    brew install gmp || true
    ;;
*)
    echo "Invalid platform! $OS_NAME"
    usage
    ;;
esac

cd "$GNUTLS_BUILD_DIR"

# Originally from: https://ftp.gnu.org/gnu/nettle/
curl --retry 3 https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2021-01-04_nettle-3.7.tar.gz --output nettle-3.7.tar.gz
tar -xzf nettle-3.7.tar.gz
cd nettle-3.7
./configure --prefix="$GNUTLS_INSTALL_DIR"/nettle \
            --disable-openssl \
            --enable-shared
make -j $JOBS
make -j $JOBS install
cd ..

# Install GnuTLS
# Originally from: https://www.gnupg.org/ftp/gcrypt/gnutls/v3.7/
curl --retry 3 https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2022-01-18_gnutls-3.7.3.tar.xz --output gnutls-3.7.3.tar.xz
tar -xJf gnutls-3.7.3.tar.xz
cd gnutls-3.7.3
PKG_CONFIG_PATH="$GNUTLS_INSTALL_DIR"/nettle/lib/pkgconfig:$PKG_CONFIG_PATH \
  ./configure --prefix="$GNUTLS_INSTALL_DIR" \
              --without-p11-kit \
              --with-included-libtasn1 \
              --with-included-unistring
make -j $JOBS
make -j $JOBS install
