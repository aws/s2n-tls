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

cd "$BUILD_DIR"
git clone https://github.com/awslabs/aws-lc.git
if [ "$IS_FIPS" -eq "1" ]; then
  cd aws-lc
  git checkout -b fips-2021-10-20 origin/fips-2021-10-20
  cd ..
fi

mkdir build
cd build

cmake ../aws-lc -GNinja -DBUILD_SHARED_LIBS=1 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" -DFIPS="${IS_FIPS}"
ninja -j "${JOBS}" install

popd

exit 0
