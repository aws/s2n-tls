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
set -eo pipefail

usage() {
    echo "test_install_shared_and_static.sh build_dir"
    echo "Checks that installed s2n-config.cmake chooses appropriately between shared and static."
    echo "Note that you MUST build against the version of libcrypto that's actually installed on the system,"
    echo "because installing libs2n.so forces it to use the system's libcrypto.so."
    exit 1
}

if [ "$#" -ne 1 ]; then
    usage
fi

WORK_DIR=$1

source codebuild/bin/s2n_setup_env.sh
source codebuild/bin/jobs.sh

COMMON_S2N_BUILD_ARGS=(-H. -DCMAKE_PREFIX_PATH=$LIBCRYPTO_ROOT -DBUILD_TESTING=OFF)

# create installation dir with libs2n.so
if [ ! -d $WORK_DIR/s2n-install-shared ]; then
    (set -x; cmake -B$WORK_DIR/s2n-build-shared -DCMAKE_INSTALL_PREFIX=$WORK_DIR/s2n-install-shared -DBUILD_SHARED_LIBS=ON ${COMMON_S2N_BUILD_ARGS[@]})
    (set -x; cmake --build $WORK_DIR/s2n-build-shared --target install -- -j $JOBS)
fi

# create installation dir with libs2n.a
if [ ! -d $WORK_DIR/s2n-install-static ]; then
    (set -x; cmake -B$WORK_DIR/s2n-build-static -DCMAKE_INSTALL_PREFIX=$WORK_DIR/s2n-install-static -DBUILD_SHARED_LIBS=OFF ${COMMON_S2N_BUILD_ARGS[@]})
    (set -x; cmake --build $WORK_DIR/s2n-build-static --target install -- -j $JOBS)
fi

# create installation dir with both libs2n.so and libs2n.a
if [ ! -d $WORK_DIR/s2n-install-both ]; then
    (set -x; cmake -B$WORK_DIR/s2n-build-shared-both -DCMAKE_INSTALL_PREFIX=$WORK_DIR/s2n-install-both -DBUILD_SHARED_LIBS=ON ${COMMON_S2N_BUILD_ARGS[@]})
    (set -x; cmake --build $WORK_DIR/s2n-build-shared-both --target install -- -j $JOBS)

    (set -x; cmake -B$WORK_DIR/s2n-build-static-both -DCMAKE_INSTALL_PREFIX=$WORK_DIR/s2n-install-both -DBUILD_SHARED_LIBS=OFF  ${COMMON_S2N_BUILD_ARGS[@]})
    (set -x; cmake --build $WORK_DIR/s2n-build-static-both --target install -- -j $JOBS)
fi

# write out source of a small cmake project, containing:
# - mylib: a library that uses s2n
# - myapp: executable that uses mylib
rm -rf $WORK_DIR/myapp-src
mkdir -p $WORK_DIR/myapp-src

cat <<EOF > $WORK_DIR/myapp-src/mylib.c
extern int s2n_init(void);

void mylib_init(void) {
    s2n_init();
}
EOF

cat <<EOF > $WORK_DIR/myapp-src/myapp.c
extern void mylib_init(void);

int main() {
    mylib_init();
}
EOF

cat <<EOF > $WORK_DIR/myapp-src/CMakeLists.txt
cmake_minimum_required (VERSION 3.0)
project (myapp C)

add_library(mylib mylib.c)
find_package(s2n REQUIRED)
target_link_libraries(mylib PRIVATE AWS::s2n)

add_executable(myapp myapp.c)
target_link_libraries(myapp PRIVATE mylib)
EOF

# build myapp and mylib, confirm that expected type of libs2n is used
build_myapp() {
    local BUILD_SHARED_LIBS=$1 # ("BUILD_SHARED_LIBS=ON" or "BUILD_SHARED_LIBS=OFF")
    local S2N_INSTALL_DIR=$2 # which s2n-install dir should be used
    local LIBS2N_EXPECTED=$3 # ("libs2n.so" or "libs2n.a") which type of libs2n is expected to be used

    echo "---------------------------------------------------------------------"
    echo "building myapp with $BUILD_SHARED_LIBS looking-in:$S2N_INSTALL_DIR should-use:$LIBS2N_EXPECTED"

    local MYAPP_BUILD_DIR=$WORK_DIR/myapp-build
    rm -rf $MYAPP_BUILD_DIR/

    local S2N_INSTALL_PATH=$(realpath $WORK_DIR/$S2N_INSTALL_DIR)

    (set -x; cmake -H$WORK_DIR/myapp-src -B$MYAPP_BUILD_DIR -D$BUILD_SHARED_LIBS "-DCMAKE_PREFIX_PATH=$S2N_INSTALL_PATH;$LIBCRYPTO_ROOT")
    (set -x; cmake --build $MYAPP_BUILD_DIR)

    LDD_OUTPUT=$(ldd $MYAPP_BUILD_DIR/myapp)
    echo "$LDD_OUTPUT"

    if echo "$LDD_OUTPUT" | grep -q libs2n.so; then
        local LIBS2N_ACTUAL=libs2n.so
    else
        local LIBS2N_ACTUAL=libs2n.a
    fi

    if [ $LIBS2N_ACTUAL != $LIBS2N_EXPECTED ]; then
        echo "test failure: used $LIBS2N_ACTUAL, but expected to use $LIBS2N_EXPECTED"
        exit 1
    fi
}

# if only shared libs2n.so is available, that's what should get used
build_myapp BUILD_SHARED_LIBS=ON s2n-install-shared libs2n.so
build_myapp BUILD_SHARED_LIBS=OFF s2n-install-shared libs2n.so

# if only static libs2n.a is available, that's what should get used
build_myapp BUILD_SHARED_LIBS=ON s2n-install-static libs2n.a
build_myapp BUILD_SHARED_LIBS=OFF s2n-install-static libs2n.a

# if both libs2n.so and libs2n.a are available...
build_myapp BUILD_SHARED_LIBS=ON s2n-install-both libs2n.so # should choose libs2n.so
build_myapp BUILD_SHARED_LIBS=OFF s2n-install-both libs2n.a # should choose libs2n.a
