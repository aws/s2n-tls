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
    echo "install_awslc.sh build_dir install_dir"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
source codebuild/bin/jobs.sh

# Disable go proxy.  see https://github.com/golang/go/issues/33985
go env -w GOPRIVATE="*"

cd "$BUILD_DIR"
git clone --depth 1 https://github.com/awslabs/aws-lc.git
cd aws-lc
cmake . -Bbuild -GNinja -DBUILD_SHARED_LIBS=1 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}"
cd build
ninja -j "${JOBS}" install

popd

exit 0
