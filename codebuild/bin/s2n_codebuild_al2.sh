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

set -e

source codebuild/bin/s2n_setup_env.sh
# Use prlimit to set the memlock limit to unlimited for linux. OSX is unlimited by default
# Codebuild Containers aren't allowing prlimit changes (and aren't being caught with the usual cgroup check)
if [[ "$OS_NAME" == "linux" && -n "$CODEBUILD_BUILD_ARN" ]]; then
    PRLIMIT_LOCATION=`which prlimit`
    sudo -E ${PRLIMIT_LOCATION} --pid "$$" --memlock=unlimited:unlimited;
fi

CMAKE_PQ_OPTION="S2N_NO_PQ=False"
if [[ -n "$S2N_NO_PQ" ]]; then
    CMAKE_PQ_OPTION="S2N_NO_PQ=True"
fi

# Linker flags are a workaround for openssl
case "$TESTS" in
  "unit") cmake . -Bbuild -DCMAKE_EXE_LINKER_FLAGS="-lcrypto -lz" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -D${CMAKE_PQ_OPTION} -DS2N_BLOCK_NONPORTABLE_OPTIMIZATIONS=True
          cmake --build ./build -j $(nproc)
          cmake --build ./build --target test -- ARGS="-L unit"
	  ;;
  *) echo "Unknown test"
     exit 1;;
esac

