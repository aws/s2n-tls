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

# BoringSSL doesn't have tags or versions in the Github repo.
# This commit represents the latest version that S2N is compatible
# with. It prevents our build system from breaking when BoringSSL
# is updated.
mkdir boringssl
cd boringssl
git init
git remote add origin https://github.com/google/boringssl.git
git fetch origin --depth=1 3743aafdacff2f7b083615a043a37101f740fa53
git reset --hard FETCH_HEAD

git checkout 3743aafdacff2f7b083615a043a37101f740fa53
mkdir ../build
cd ../build

cmake ../boringssl -DBUILD_SHARED_LIBS=1 -DCMAKE_BUILD_TYPE=Release
make -j $JOBS

# BoringSSL does not define any install configuration in their CMake config, copy the stuff we know we need
mkdir -p "${INSTALL_DIR}/lib"
mkdir -p "${INSTALL_DIR}/bin"
cp crypto/libcrypto.so "${INSTALL_DIR}/lib/libcrypto.so"
cp tool/bssl "${INSTALL_DIR}/bin/bssl"
cp -r ../boringssl/include "$INSTALL_DIR"

popd

exit 0
