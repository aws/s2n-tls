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

usage() {
    echo "install_openssl_0_9_8.sh build_dir install_dir os_name"
    exit 1
}

if [ "$#" -ne "3" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
PLATFORM=$3
RELEASE=0.9.8zh

# Changing LD_LIBRARY_PATH and expecting OS utils to work is a trap.
OLD_LD_LIBRARY_PATH="$LD_LIBRARY_PATH"
unset LD_LIBRARY_PATH

cd "$BUILD_DIR"
curl --retry 3 -L https://www.openssl.org/source/old/0.9.x/openssl-${RELEASE}.tar.gz --output openssl-${RELEASE}.tar.gz
tar xzvf openssl-0.9.8zh.tar.gz
cd openssl-0.9.8zh

if [ "$PLATFORM" == "linux" ]; then
    CONFIGURE="./config -d"
elif [ "$PLATFORM" == "osx" ]; then
    CONFIGURE="./Configure darwin64-x86_64-cc"
else
    echo "Invalid platform! $PLATFORM"
    usage
fi

$CONFIGURE --prefix="$INSTALL_DIR"

make depend
make -j8
make install

popd

export LD_LIBRARY_PATH=$OLD_LD_LIBRARY_PATH
exit 0

