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

set -eu
pushd "$(pwd)"
source codebuild/bin/jobs.sh

VERSION=$0
BUILD_DIR=$1
INSTALL_DIR=$2
PLATFORM=$3

usage() {
    echo "$VERSION build_dir install_dir os_name"
    exit 1
}

openssl_0_9_8(){
    cd "$BUILD_DIR"
    curl --retry 3 -L https://www.openssl.org/source/old/0.9.x/openssl-${RELEASE}.tar.gz --output openssl-${RELEASE}.tar.gz
    tar xzvf openssl-0.9.8zh.tar.gz
    cd openssl-0.9.8zh
}

openssl_1_0_2(){
    cd "$BUILD_DIR"
    curl --retry 3 -L https://github.com/openssl/openssl/archive/OpenSSL_${RELEASE}.zip --output openssl-OpenSSL_${RELEASE}.zip
    unzip openssl-OpenSSL_${RELEASE}.zip
    cd openssl-OpenSSL_${RELEASE}

    CONFIGURE+=" -g3 -fPIC no-libunbound no-gmp no-jpake no-krb5 no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace \
            no-store no-zlib no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia no-bf no-ripemd \
            no-dsa no-ssl2 no-capieng -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS"

}

openssl_1_1_1(){
    cd "$BUILD_DIR"
    curl --retry 3 -L https://github.com/openssl/openssl/archive/OpenSSL_${RELEASE}.zip --output OpenSSL_${RELEASE}.zip
    unzip OpenSSL_${RELEASE}.zip
    cd openssl-OpenSSL_${RELEASE}

    # Use g3 to get debug symbols in libcrypto to chase memory leaks
    CONFIGURE+=" -g3 -fPIC \
         no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib \
         no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia \
         no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng \
         -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS"
}

# Main
if [ "$#" -ne "3" ]; then
    usage
fi

# Protect from LD_LIBRARY_PATH pollution.
LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-"none"}
OLD_LD_LIBRARY_PATH="$LD_LIBRARY_PATH"
unset LD_LIBRARY_PATH

# Which platform are we configuring for?
if [ "$PLATFORM" == "linux" ]; then
    CONFIGURE="./config -d"
elif [ "$PLATFORM" == "osx" ]; then
    CONFIGURE="./Configure darwin64-x86_64-cc"
else
    echo "Invalid platform! $PLATFORM"
    usage
fi

case $VERSION in
    *"install_openssl_0_9_8.sh")
        RELEASE=0.9.8zh
        openssl_0_9_8;;
    *"install_openssl_1_0_2.sh")
        RELEASE=1_0_2-stable
        openssl_1_0_2;;
    *"install_openssl_1_1_1.sh")
        RELEASE=1_1_1h
        openssl_1_1_1;;
    *)
        echo "Unmatched OpenSSL install version $VERSION"
esac

export LD_LIBRARY_PATH=$OLD_LD_LIBRARY_PATH
$CONFIGURE --prefix="$INSTALL_DIR"
make -j $JOBS depend
make -j $JOBS
make -j $JOBS install_sw
echo -e "Openssl version info:\n$($INSTALL_DIR/openssl version)\n$($INSTALL_DIR/openssl version -f)"
popd

exit 0

