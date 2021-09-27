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

# Set the version of GCC as Default if it's required
if [[ -n "$GCC_VERSION" ]] && [[ "$GCC_VERSION" != "NONE" ]]; then
    alias gcc=$(which gcc-$GCC_VERSION);
fi

BUILD_DIR=$1
INSTALL_DIR=$2
source codebuild/bin/jobs.sh

mkdir "$BUILD_DIR/s2n"
# In case $BUILD_DIR is a subdirectory of current directory
for file in *;do test "$file" != "$BUILD_DIR" && cp -r "$file" "$BUILD_DIR/s2n";done
cd "$BUILD_DIR"
git clone --recurse-submodules https://github.com/awslabs/aws-crt-cpp.git
# Replace S2N
rm -r aws-crt-cpp/crt/s2n
mv s2n aws-crt-cpp/crt/
mkdir build
cd build

cmake ../aws-crt-cpp -GNinja -DBUILD_DEPS=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}"
ninja -j "${JOBS}" install
ninja test

popd

exit 0
