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
#

set -eu

source codebuild/bin/s2n_setup_env.sh
# Used to test if we're running in CodeBuild
CODEBUILD_BUILD_ARN_="${CODEBUILD_BUILD_ARN:-}"

if [[ ${DISTRO} != "amazon linux" ]]; then
    echo "Target Amazon Linux, but running on $DISTRO: Nothing to do."
    exit 1;
else
    # AL2023 case
    BUILD_FLAGS="-DCMAKE_BUILD_TYPE=RelWithDebInfo"
    # AL2 case; Linker flags are a workaround for system openssl
    if [[ ${VERSION_ID} == '2' ]]; then
       BUILD_FLAGS=$(echo -e '-DCMAKE_EXE_LINKER_FLAGS="-lcrypto -lz" \
         -DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    fi
fi

# Use prlimit to set the memlock limit to unlimited for linux. OSX is unlimited by default
# Codebuild Containers aren't allowing prlimit changes (and aren't being caught with the usual cgroup check)
if [[ "$OS_NAME" == "linux" && -z "$CODEBUILD_BUILD_ARN_" ]]; then
    PRLIMIT_LOCATION=$(which prlimit)
    sudo -E ${PRLIMIT_LOCATION} --pid "$$" --memlock=unlimited:unlimited;
fi

case "$TESTS" in
  "unit")
    eval cmake . -Bbuild "${BUILD_FLAGS}"
    cmake --build ./build -j "$(nproc)"
    CTEST_PARALLEL_LEVEL="$(nproc)" cmake --build ./build --target test -- ARGS="-L unit --output-on-failure"
    ;;
  *) echo "Unknown test"; exit 1;;
esac
