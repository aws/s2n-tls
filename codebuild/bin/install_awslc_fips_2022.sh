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

set -eu
pushd "$(pwd)"

usage() {
    echo "install_awslc_fips_2022.sh build_dir install_dir"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2

if [[ ! -f "$(which clang)" ]]; then
  echo "Could not find clang"
  exit 1
fi

AWSLC_VERSION=AWS-LC-FIPS-2.0.17

mkdir -p "$BUILD_DIR" || true
cd "$BUILD_DIR"
# --branch can also take tags and detaches the HEAD at that commit in the resulting repository
# --depth 1 Create a shallow clone with a history truncated to 1 commit
git clone https://github.com/awslabs/aws-lc.git --branch "$AWSLC_VERSION" --depth 1

build() {
    shared=$1
    cmake . \
      -Bbuild \
      -GNinja \
      -DBUILD_SHARED_LIBS="${shared}" \
      -DCMAKE_BUILD_TYPE=relwithdebinfo \
      -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" \
      -DCMAKE_C_COMPILER=$(which clang) \
      -DCMAKE_CXX_COMPILER=$(which clang++) \
      -DFIPS=1
    ninja -j "$(nproc)" -C build install
    ninja -C build clean
}

build 0
build 1

exit 0
