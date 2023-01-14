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

set -e

source codebuild/bin/s2n_setup_env.sh

# LLVM complains about corrupt coverage information
# for static targets, so compile to a shared lib
# instead.
cmake . -Bbuild \
    -DCOVERAGE=ON \
    -DBUILD_SHARED_LIBS=ON

cmake --build ./build -- -j $(nproc)

echo "done with the build"
