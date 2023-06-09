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

WORK_DIR=$1

if [ ! -z "$NIX_STORE" ]; then
    OPENSSL=$(which openssl)
    LIBCRYPTO_ROOT=$(nix-store --query $OPENSSL)
else
    source codebuild/bin/s2n_setup_env.sh
fi

S2N_BUILD_ARGS=(-H. -DCMAKE_PREFIX_PATH=$LIBCRYPTO_ROOT -DBUILD_TESTING=OFF)

# create installation dir with libs2n.so
if [ ! -d $WORK_DIR/s2n-install-shared ]; then
    (set -x; cmake -B$WORK_DIR/s2n-build-shared -DCMAKE_INSTALL_PREFIX=$WORK_DIR/s2n-install-shared -DBUILD_SHARED_LIBS=ON ${S2N_BUILD_ARGS[@]})
    (set -x; cmake --build $WORK_DIR/s2n-build-shared --target install -- -j $(nproc))
fi

# Compile the test file
$CC -Wl,-rpath $LIBCRYPTO_ROOT -o s2n_dynamic_load_test codebuild/bin/s2n_dynamic_load_test.c -ldl -lpthread

LDD_OUTPUT=$(ldd s2n_dynamic_load_test)

# Confirm executable doesn't have libs2n.so loaded
if echo "$LDD_OUTPUT" | grep -q libs2n; then
    echo "test failure: libs2n should not appear in ldd output"
    exit 1
fi

# Run the test with the path to libs2n
echo "Running s2n_dynamic_load_test"
LD_LIBRARY_PATH=$LIBCRYPTO_ROOT/lib ./s2n_dynamic_load_test $WORK_DIR/s2n-install-shared/lib/libs2n.so
returncode=$?
if [ $returncode -ne 0 ]; then
    echo "test failure: s2n_dynamic_load_test did not succeed"
    exit 1
fi
echo "Passed s2n_dynamic_load_test"
