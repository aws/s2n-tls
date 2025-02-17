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

usage() {
    echo "$0 build_dir install_dir"
    exit 1
}

check_dep(){
    if [[ ! -f "$(which $1)" ]]; then
        echo "Could not find $1"
        exit 1
    fi
}

clone(){
    git clone https://github.com/awslabs/aws-lc.git --branch "$AWSLC_VERSION" --depth 1 $BUILD_DIR
    cd "$BUILD_DIR"
}

build() {
    echo "Building with shared library=$1"
    cmake $BUILD_DIR \
      -Bbuild \
      -GNinja \
      -DBUILD_SHARED_LIBS=$1 \
      -DCMAKE_BUILD_TYPE=relwithdebinfo \
      -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" \
      -DCMAKE_C_COMPILER=$(which clang) \
      -DCMAKE_CXX_COMPILER=$(which clang++) \
      -DFIPS="true"
    ninja -j "$(nproc)" -C build install
    ninja -C build clean
}

# main
if [ "$#" -ne "2" ]; then
    usage
fi

# Ensure tooling is available
check_dep clang
check_dep ninja
check_dep go

BUILD_DIR=$1
INSTALL_DIR=$2
# Use the script name to determine version
INSTALLER=$(basename $0)

# Map installer title to specific feature branch/tag:
case $INSTALLER in
  "install_awslc_fips_2022.sh")
    AWSLC_VERSION=AWS-LC-FIPS-2.0.17
    ;;
  "install_awslc_fips_2024.sh")
    AWSLC_VERSION=AWS-LC-FIPS-3.0.0
    ;;
  *)
    echo "Unknown version: $0"
    usage
    ;;
esac

clone
# Static lib
build false

# Shared lib
build true

rm -rf $BUILD_DIR