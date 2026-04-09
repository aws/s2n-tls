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
    echo "build_aws_crt_cpp.sh build_dir install_dir"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

source codebuild/bin/s2n_setup_env.sh

BUILD_DIR=$1
INSTALL_DIR=$2

# Make sure there isn't another source tree hanging around.
rm -rf /opt/s2n-tls || true
mkdir -p "$BUILD_DIR/s2n"
# In case $BUILD_DIR is a subdirectory of current directory
for file in *;do test "$file" != "$BUILD_DIR" && cp -r "$file" "$BUILD_DIR/s2n";done
cd "$BUILD_DIR"
# Pin to commit before "Mqtt test refactor" PR which broke WS test skip logic
# in CI environments without IoT credentials. See: https://github.com/awslabs/aws-crt-cpp
# TODO: Unpin once aws-crt-cpp fixes the skip logic for WS tests
git clone --recurse-submodules https://github.com/awslabs/aws-crt-cpp.git
cd aws-crt-cpp
git checkout 7cb4eaa18cfbcabcc24f8ef3b9e4c2f18c77348c
git submodule update --init --recursive
cd ..
# Replace S2N
rm -r aws-crt-cpp/crt/s2n
mv s2n aws-crt-cpp/crt/

cmake ./aws-crt-cpp \
    -Bbuild \
    -GNinja \
    -DENFORCE_SUBMODULE_VERSIONS=off \
    -DBUILD_DEPS=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}"
ninja -C ./build install
CTEST_OUTPUT_ON_FAILURE=1 CTEST_PARALLEL_LEVEL=$(nproc) ninja -C ./build test

popd

exit 0
