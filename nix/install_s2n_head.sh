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

set -eux

usage() {
    echo "install_s2n_head.sh build_dir"
    exit 1
}

if [ "$#" -ne "1" ]; then
    usage
fi

BUILD_DIR=$1
cd "$SRC_ROOT"

if [[ ! -x "$SRC_ROOT/build/bin/s2nc_head" ]]; then
    if [[ ! -d "s2n_head" ]]; then
        # Clone the most recent s2n commit
        git clone -v --depth=1 https://github.com/aws/s2n-tls s2n_head
    fi
    cmake ./s2n_head -B$BUILD_DIR -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=on
    cmake --build $BUILD_DIR -- -j $(nproc)

    # Copy new executables to bin directory
    cp -f "$BUILD_DIR"/bin/s2nc "$SRC_ROOT"/build/bin/s2nc_head
    cp -f "$BUILD_DIR"/bin/s2nd "$SRC_ROOT"/build/bin/s2nd_head
fi

exit 0
