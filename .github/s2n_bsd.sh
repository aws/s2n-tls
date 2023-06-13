#!/bin/sh
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
set -eu

# FreeBSD and OpenBSD have different ways of getting CPU count
# see https://serverfault.com/questions/203207/how-do-i-count-the-number-of-processors-on-an-openbsd-system
if [ "$(uname)" = 'FreeBSD' ]; then
    export CTEST_PARALLEL_LEVEL=$(sysctl hw.ncpu | awk '{print $2}')
else
    export CTEST_PARALLEL_LEVEL=$(sysctl -n hw.ncpuonline)
fi

errors=0
onerror() {
  errors=$(($errors+1))
}

mkdir -p output

cmake . -Brelease -GNinja -DCMAKE_BUILD_TYPE=Release
cmake --build ./release -j $CTEST_PARALLEL_LEVEL
ninja -C release test || onerror
mv release/Testing/Temporary output/release
# reduce the number of files to copy back
rm -rf release

cmake . -Bbuild -GNinja -DCMAKE_BUILD_TYPE=Debug
cmake --build ./build -j $CTEST_PARALLEL_LEVEL
ninja -C build test || onerror
mv build/Testing/Temporary output/debug
# reduce the number of files to copy back
rm -rf build

exit $errors
