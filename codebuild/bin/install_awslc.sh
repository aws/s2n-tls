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

set -e
pushd "$(pwd)"

usage() {
    echo "install_awslc.sh build_dir install_dir is_fips"
    exit 1
}

if [ "$#" -ne "3" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
IS_FIPS=$3

source codebuild/bin/jobs.sh

# These tags represents the latest versions that S2N is compatible
# with. It prevents our build system from breaking when AWS-LC
# is updated, last done on 2023-02-22.
if [ "$IS_FIPS" == "1" ]; then
  AWSLC_VERSION=AWS-LC-FIPS-1.0.3
else
  AWSLC_VERSION=v1.17.4
fi
mkdir -p "$BUILD_DIR"||true
cd "$BUILD_DIR"
echo "Checking out tag=$AWSLC_VERSION"
# --branch can also take tags and detaches the HEAD at that commit in the resulting repository
# --depth 1 Create a shallow clone with a history truncated to 1 commit
git clone https://github.com/awslabs/aws-lc.git --branch "$AWSLC_VERSION" --depth 1

install_awslc() {
	echo "Building with shared library=$1"
	cmake ./aws-lc -Bbuild -GNinja -DBUILD_SHARED_LIBS=$1 -DCMAKE_BUILD_TYPE=relwithdebinfo -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" -DFIPS="${IS_FIPS}"
	ninja -j "${JOBS}" -C build install
	ninja -C build clean
}

if [ "$IS_FIPS" != "1" ]; then
  install_awslc 0
fi

install_awslc 1

exit 0
