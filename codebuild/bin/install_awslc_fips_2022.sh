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

set -e
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

source codebuild/bin/jobs.sh

# There are currently no AWSLC release tags for the 2022 FIPS branch. The
# following is the latest commit in this branch as of 4/5/23:
# https://github.com/aws/aws-lc/commits/fips-2022-11-02
AWSLC_VERSION=03ea7816359a3e1babdf9f2cd0e694977c36ebbc

mkdir -p "$BUILD_DIR" || true
cd "$BUILD_DIR"
git clone https://github.com/aws/aws-lc.git
cd aws-lc
git checkout "${AWSLC_VERSION}"

build() {
    shared=$1
    cmake . -Bbuild -GNinja -DBUILD_SHARED_LIBS="${shared}" -DCMAKE_BUILD_TYPE=relwithdebinfo -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" -DFIPS=1
    ninja -j "${JOBS}" -C build install
    ninja -C build clean
}

build 0
build 1

exit 0
