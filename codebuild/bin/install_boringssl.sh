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

set -ex
pushd "$(pwd)"

usage() {
    echo "install_boringssl.sh build_dir install_dir"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
source codebuild/bin/jobs.sh

cd "$BUILD_DIR"
git clone https://github.com/google/boringssl.git
mkdir build
cd build

cmake ../boringssl
make -j $JOBS

mkdir -p "${INSTALL_DIR}/lib"
cp crypto/libcrypto.a "${INSTALL_DIR}/lib/libcrypto.a"
cp -r ../boringssl/include "$INSTALL_DIR"

popd

exit 0
