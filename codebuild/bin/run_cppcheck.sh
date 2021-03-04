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

usage() {
    echo "run_cppcheck.sh install_dir"
    exit 1
}

if [ "$#" -ne "1" ]; then
    usage
fi

INSTALL_DIR=$1

CPPCHECK_EXECUTABLE=${INSTALL_DIR}/cppcheck

ARGS="--std=c99 --error-exitcode=-1 --quiet --force --inline-suppr"
# list out each check so we don't include unusedFunction warnings - they don't
# work with DEFER_CLEANUP
ARGS+=" --enable=warning,style,performance,portability,information,missingInclude"
ARGS+=" --suppressions-list=codebuild/bin/cppcheck_suppressions.txt"
ARGS+=" --suppress=unusedFunction"

if [ ! -z "$CPPCHECK_CACHE_DIR" ]; then
  ARGS+=" --cppcheck-build-dir=$CPPCHECK_CACHE_DIR"
  mkdir -p $CPPCHECK_CACHE_DIR
fi

if [ ! -z "$JOBS" ]; then
  ARGS+=" -j $JOBS"
fi

ARGS+=" -I . -I ./tests api bin crypto error stuffer tests/unit tls utils"

$CPPCHECK_EXECUTABLE --version
$CPPCHECK_EXECUTABLE --template='[{file}:{line}]: ({severity}:{id}) {message}' $ARGS
CODE=$?
if [ $CODE != 0 ];
then
	printf "\\033[31;1mFAILED cppcheck\\033[0m\\n"
	exit -1
else
	printf "\\033[32;1mPASSED cppcheck\\033[0m\\n"
fi
