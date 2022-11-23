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

usage() {
    echo "run_cppcheck.sh install_dir cache_dir"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

INSTALL_DIR=$1
CACHE_DIR=$2
mkdir -p "$CACHE_DIR" || true

CPPCHECK_EXECUTABLE=${INSTALL_DIR}/cppcheck

FAILED=0
$CPPCHECK_EXECUTABLE --version

# NOTE: cppcheck should be run in single thread to ensure we are check for `unusedFunction`. Do not add the `-j` flag.
$CPPCHECK_EXECUTABLE --std=c99 --error-exitcode=-1 --force --enable=all -j 2 --template='[{file}:{line}]: ({severity}:{id}) {message}' --inline-suppr --cppcheck-build-dir "$CACHE_DIR" --suppressions-list=codebuild/bin/cppcheck_suppressions.txt -I . -I api || FAILED=1
# remaining: ./tests bin crypto error stuffer ./tests/unit tls utils

if [ $FAILED == 1 ];
then
	printf "\\033[31;1mFAILED cppcheck\\033[0m\\n"
	exit -1
else
	printf "\\033[32;1mPASSED cppcheck\\033[0m\\n"
fi
