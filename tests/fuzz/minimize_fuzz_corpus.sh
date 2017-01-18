#!/bin/bash
# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

usage() {
    echo "Usage: minimizeFuzzCorpus.sh TEST_NAME"
    exit 1
}

if [ "$#" -ne "1" ]; then
    usage
fi

# Add Defaults to end of paths in case they aren't present
DYLD_LIBRARY_PATH="$DYLD_LIBRARY_PATH:../../lib/:../testlib/:../../libcrypto-root/lib"
LD_LIBRARY_PATH="$LD_LIBRARY_PATH:../../lib/:../testlib/:../../libcrypto-root/lib:"

TEST_NAME=$1

mv ./corpus/${TEST_NAME} ./corpus/${TEST_NAME}_OLD
mkdir ./corpus/${TEST_NAME}
./${TEST_NAME} -merge=1 ./corpus/${TEST_NAME} ./corpus/${TEST_NAME}

mv /corpus/${TEST_NAME}_OLD_${RANDOM}