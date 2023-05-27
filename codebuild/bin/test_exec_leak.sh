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

set -e

# Test that all file descriptors are properly cleaned up when `exec`ing from
# from an initialized s2n-tls process.

source codebuild/bin/s2n_setup_env.sh
source codebuild/bin/jobs.sh

function build() {
  echo "=== BUILDING $1 ==="
  cmake . -B$1 -DCMAKE_PREFIX_PATH=$TARGET_LIBCRYPTO_PATH ${@:2}
  cmake --build $1 -- -j $JOBS
}

function fail() {
    echo "test failure: $1"
    exit 1
}

function write_exec_app() {
cat <<EOF > build/detect_exec_leak.c
#include <s2n.h>
#include "unistd.h"

int main() {
    s2n_init();
    execl("build/bin/detect_exec_leak_finish", "", NULL);
    return 0;
}
EOF
}

function write_exec_finish_app() {
cat <<EOF > build/detect_exec_leak_finish.c
#include <s2n.h>

int main() {
    s2n_init();
    s2n_cleanup();

    /* close std* file descriptors so valgrind output is less noisy */
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);
    return 0;
}
EOF
}

# download libcrypto if its not available
TARGET_LIBCRYPTO="${S2N_LIBCRYPTO//[-.]/_}"
TARGET_LIBCRYPTO_PATH="${TEST_DEPS_DIR}/${S2N_LIBCRYPTO}"
if [ ! -f $TARGET_LIBCRYPTO_PATH/lib/libcrypto.a ]; then
    ./codebuild/bin/install_${TARGET_LIBCRYPTO}.sh $TARGET_LIBCRYPTO_PATH/src $TARGET_LIBCRYPTO_PATH linux
fi

# build s2n-tls
build build -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=on

# compile the test app for exec leak test
mkdir -p build/valgrind_log_dir
write_exec_app
write_exec_finish_app
cc -Iapi build/detect_exec_leak.c build/lib/libs2n.so -o build/bin/detect_exec_leak
cc -Iapi build/detect_exec_leak_finish.c build/lib/libs2n.so -o build/bin/detect_exec_leak_finish

# run valgrind with track-fds enabled
valgrind_log_dir=valgrind_log_dir
for test_file in detect_exec_leak detect_exec_leak_finish; do
    LD_LIBRARY_PATH="build/lib:$TARGET_LIBCRYPTO_PATH/lib:$LD_LIBRARY_PATH" S2N_VALGRIND=1 \
        valgrind --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all \
        --run-libc-freeres=yes -q --gen-suppressions=all --track-fds=yes \
        --leak-resolution=high --undef-value-errors=no --trace-children=yes \
        --suppressions=tests/unit/valgrind.suppressions --log-file="build/$valgrind_log_dir/$test_file" \
    	  build/bin/$test_file

    # search for all leaked file descriptors, excluding the valgrind_log_dir file
    cat build/$valgrind_log_dir/$test_file | \
        grep "Open file descriptor" | \
        grep --invert-match $valgrind_log_dir \
        && fail "file leak detected while running $test_file"
done

echo pass
