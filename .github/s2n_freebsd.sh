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
export CTEST_PARALLEL_LEVEL=$(sysctl hw.ncpu | awk '{print $2}')

cmake . -Bbuild -GNinja -DCMAKE_BUILD_TYPE=Release
cmake --build ./build -j $CTEST_PARALLEL_LEVEL
ninja -C build test
cmake --build ./build --target clean #Saves on copy back rsync time

cmake . -Bbuild -GNinja -DCMAKE_BUILD_TYPE=Debug
cmake --build ./build -j $CTEST_PARALLEL_LEVEL
ninja -C build test
cmake --build ./build --target clean #Saves on copy back rsync time