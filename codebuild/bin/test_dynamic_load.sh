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
#

# This script compiles s2n-tls as a shared library and compiles a test 
# without linking to the library. This enables us to test behavior when 
# s2n-tls is dynamically loaded.
set -eo pipefail

WORK_DIR=$1

source codebuild/bin/s2n_setup_env.sh
source codebuild/bin/jobs.sh

S2N_BUILD_ARGS=(-H. -DCMAKE_PREFIX_PATH=$LIBCRYPTO_ROOT -DBUILD_TESTING=OFF)

# create installation dir with libs2n.so
if [ ! -d $WORK_DIR/s2n-install-shared ]; then
    (set -x; cmake -B$WORK_DIR/s2n-build-shared -DCMAKE_INSTALL_PREFIX=$WORK_DIR/s2n-install-shared -DBUILD_SHARED_LIBS=ON ${S2N_BUILD_ARGS[@]})
    (set -x; cmake --build $WORK_DIR/s2n-build-shared --target install -- -j $JOBS)
fi

# Compile the dynamic load test without linking to libs2n.so
gcc -o s2n_dynamic_load_test tests/unit/s2n_dynamic_load_test.c -ldl -lpthread -L$WORK_DIR/s2n-install-shared/lib -ls2n

LDD_OUTPUT=$(ldd s2n_dynamic_load_test)

# Confirm executable doesn't have libs2n linked
if echo "$LDD_OUTPUT" | grep -q libs2n; then
    echo "test failure: libs2n should not appear in ldd output"
    exit 1
fi

# Run the test with the path to libs2n
./s2n_dynamic_load_test $WORK_DIR/s2n-install-shared/lib/libs2n.so