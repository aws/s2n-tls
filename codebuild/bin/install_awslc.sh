#!/usr/bin/env bash
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
    echo -e "\ninstall_awslc.sh build_dir install_dir"
    echo -e "\tIf you need FIPS, use the FIPS specific install script.\n"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
GH_RELEASE_URL="https://api.github.com/repos/aws/aws-lc/releases"

if [[ ! -f "$(which clang)" ]]; then
  echo "Could not find clang"
  exit 1
fi

# Ask GitHub for the latest v1.x release.
AWSLC_VERSION=$(curl --silent "$GH_RELEASE_URL" | \
        grep -Po '"tag_name": "\Kv1\..*?(?=")' |head -1)

mkdir -p "$BUILD_DIR"||true
cd "$BUILD_DIR"
echo "Checking out tag=$AWSLC_VERSION"
# --branch can also take tags and detaches the HEAD at that commit in the resulting repository
# --depth 1 Create a shallow clone with a history truncated to 1 commit
# If the curl above is throttled, fall back to a known version.
git clone https://github.com/awslabs/aws-lc.git --branch "${AWSLC_VERSION:-main}" --depth 1

install_awslc() {
    echo "Building with shared library=$1"
    cmake ./aws-lc \
      -Bbuild \
      -GNinja \
      -DBUILD_SHARED_LIBS=$1 \
      -DCMAKE_BUILD_TYPE=relwithdebinfo \
      -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" \
      -DCMAKE_C_COMPILER=$(which clang) \
      -DCMAKE_CXX_COMPILER=$(which clang++)
    ninja -j "$(nproc)" -C build install
    ninja -C build clean
}

install_awslc 0
install_awslc 1

exit 0
