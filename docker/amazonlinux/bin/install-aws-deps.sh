#!/bin/bash

# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

# This script builds and installs AWS-originated dependencies. Since we want to test
# building against both the static and shared variants, we build them twice, installing
# the results under /deps/static/install and /deps/shared/install

# This script uses the following environment variables:
# CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS - Compiler and flags configuration

set -euxo pipefail

build_pkg() {
    INSTALL_DIR=$1
    GIT_URL=$2
    GIT_REF=$3

    shift; shift; shift

    SRC_DIR=/tmp/$(basename $GIT_URL .git)
    BUILD_DIR=/tmp/build

    if ! [ -e $SRC_DIR ]; then
        mkdir -p "$(dirname "$SRC_DIR")"
        git clone --depth 1 --branch $GIT_REF "$GIT_URL" "$SRC_DIR"
    fi

    mkdir $BUILD_DIR
    (cd $BUILD_DIR &&
     export LD_LIBRARY_PATH=/deps/install &&
     cmake $SRC_DIR "$@" -DCMAKE_INSTALL_PREFIX=$root/install -DCMAKE_BUILD_TYPE=RelWithDebInfo -GNinja \
        -DCMAKE_PREFIX_PATH=/deps/install \
        -DCMAKE_C_FLAGS="$CFLAGS" \
        -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
        -DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS")
    cmake --build $BUILD_DIR
    cmake --build $BUILD_DIR --target install
    rm -rf $BUILD_DIR
}

mkdir -p /deps

for libtype in shared static; do
    if [ $libtype == shared ]; then
        CMAKE_ARGS="-DBUILD_SHARED_LIBS=ON"
    else
        CMAKE_ARGS="-DBUILD_SHARED_LIBS=OFF"
    fi

    root=/deps/$libtype

    # not installing aws-c-common anymore because aws-sdk-cpp installs it for us
    build_pkg $root/install https://github.com/aws/aws-sdk-cpp.git 1.7.163 $CMAKE_ARGS -DBUILD_ONLY=kms -DENABLE_UNITY_BUILD=ON
done
