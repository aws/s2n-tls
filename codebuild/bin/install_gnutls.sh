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

set -eu

usage() {
    echo "install_gnutls.sh build_dir install_dir os_name"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

GNUTLS_BUILD_DIR=$1
GNUTLS_INSTALL_DIR=$2
GNUTLS_VER=3.5.5
NETTLE_VER=3.3
source codebuild/bin/s2n_setup_env.sh
source codebuild/bin/jobs.sh

build_nettle(){
    # Build GnuTLS dependency nettle from source.
    cd "$GNUTLS_BUILD_DIR"

    # Originally from: https://ftp.gnu.org/gnu/nettle/nettle-3.3.tar.gz
    curl --retry 3 "https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2017-08-29_nettle-$NETTLE_VER.tar.gz" --output "nettle-$NETTLE_VER.tar.gz"
    tar -xzf "nettle-$NETTLE_VER.tar.gz"
    cd "nettle-$NETTLE_VER"
    ./configure --prefix="$GNUTLS_INSTALL_DIR"/nettle
    make -j $JOBS
    make -j $JOBS install
    cd ..
}

build_gnutls(){
    # Install GnuTLS from source
    # Originally from: ftp://ftp.gnutls.org/gcrypt/gnutls/v3.5/gnutls-3.5.5.tar.xz
    curl --retry 3 "https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2017-08-29_gnutls-$GNUTLS_VER.tar.xz" --output "gnutls-$GNUTLS_VER.tar.xz"
    tar -xJf "gnutls-$GNUTLS_VER.tar.xz"
    cd "gnutls-$GNUTLS_VER"
    ./configure LD_FLAGS="-R$GNUTLS_INSTALL_DIR/nettle/lib -L$GNUTLS_INSTALL_DIR/nettle/lib -lnettle -lhogweed" \
                NETTLE_LIBS="-R$GNUTLS_INSTALL_DIR/nettle/lib -L$GNUTLS_INSTALL_DIR/nettle/lib -lnettle" \
                NETTLE_CFLAGS="-I$GNUTLS_INSTALL_DIR/nettle/include" \
                HOGWEED_LIBS="-R$GNUTLS_INSTALL_DIR/nettle/lib -L$GNUTLS_INSTALL_DIR/nettle/lib -lhogweed" \
                HOGWEED_CFLAGS="-I$GNUTLS_INSTALL_DIR/nettle/include" \
                --without-p11-kit \
                --with-included-libtasn1 \
                --prefix="$GNUTLS_INSTALL_DIR"
    make -j $JOBS
    make -j $JOBS install
}

# libgmp is needed for libnettle
case "$DISTRO" in
  "ubuntu")
    sudo apt-get -qq install libgmp3-dev -y
    build_nettle
    build_gnutls
    ;;
  "amazon linux")
    echo "Packages are the only way to get nettle/gnutls on aarch64- and are OLDER versions."
    # TODO: rebuild nettle, gnutls packages with newer versions or flip to nix
    sudo yum install -y gmp-devel nettle-devel nettle gnutls gnutls-utils gnutls-devel
    mkdir $GNUTLS_INSTALL_DIR || true
    ln -fs /usr/lib64/libgnutls* $GNUTLS_INSTALL_DIR
    ln -fs /usr/lib64/.libgnutls* $GNUTLS_INSTALL_DIR
    ln -fs $(which gnutls-serv) $GNUTLS_INSTALL_DIR
    ln -fs $(which gnutls-cli) $GNUTLS_INSTALL_DIR
    exit 0
    ;;
"darwin" )
    # Installing an existing package is a "failure" in brew
    brew install gmp || true
    build_nettle
    build_gnutls
    ;;
*)
    echo "Invalid platform! $OS_NAME"
    usage
    ;;
esac
