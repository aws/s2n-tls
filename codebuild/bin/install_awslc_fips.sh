#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
set -eu

usage() {
    echo -e "\ninstall_awslc_fips.sh build_dir install_dir version"
    echo -e "\tversion: 2022|2024|next\n"
    exit 1
}

check_dep(){
    if [[ ! -f "$(which $1)" ]]; then
        echo "Could not find $1"
        exit 1
    fi
}

clone(){
    git clone https://github.com/awslabs/aws-lc.git --branch "$AWSLC_BRANCH" --depth 1 $BUILD_DIR
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
if [ "$#" -ne "3" ]; then
    usage
fi

# Ensure tooling is available
check_dep clang
check_dep ninja
check_dep go

BUILD_DIR=$1
INSTALL_DIR=$2
VERSION=$3
GH_RELEASE_URL="https://api.github.com/repos/aws/aws-lc/releases"

# Map version to the latest release of the certificate year.
# Note: since the next FIPS validation will be split off from main
# building main with FIPS enabled is the next candidate FIPS branch.
case $VERSION in
  "2022")
    AWSLC_BRANCH=$(curl --silent $GH_RELEASE_URL \
      |grep -Po '"tag_name": "\KAWS-LC-FIPS-2.*?(?=")' |head -1)
    ;;
  "2024")
    AWSLC_BRANCH=$(curl --silent $GH_RELEASE_URL \
      |grep -Po '"tag_name": "\KAWS-LC-FIPS-3.*?(?=")' |head -1)
    ;;
  "next")
    AWSLC_BRANCH=main
    ;;
  *)
    echo "Unknown version: $VERSION"
    usage
    ;;
esac

clone
# Static lib
build false
# Shared lib
build true

rm -rf $BUILD_DIR

