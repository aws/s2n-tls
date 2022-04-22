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
    echo "install_s2n_head.sh build_dir"
    exit 1
}

if [ "$#" -ne "1" ]; then
    usage
fi

BUILD_DIR=$1
source codebuild/bin/jobs.sh
cd "$BUILD_DIR"

# Clone the most recent s2n commit
git clone --depth=1 https://github.com/aws/s2n-tls s2n_head
cmake ./s2n_head -Bbuild -DCMAKE_PREFIX_PATH="$LIBCRYPTO_ROOT" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=on
cmake --build ./build -- -j $JOBS

# Copy new executables to bin directory
cp -f "$BUILD_DIR"/build/bin/s2nc "$BASE_S2N_DIR"/bin/s2nc_head
cp -f "$BUILD_DIR"/build/bin/s2nd "$BASE_S2N_DIR"/bin/s2nd_head

popd

exit 0
