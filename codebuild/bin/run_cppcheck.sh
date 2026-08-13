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

CPPCHECK_EXECUTABLE=$(which cppcheck)
CPPCHECK_BUILD_DIR=".cppcheck-build-dir"
DIRS="api bin crypto error stuffer ./tests/unit tls utils"

mkdir -p "$CPPCHECK_BUILD_DIR"

$CPPCHECK_EXECUTABLE --version

FAILED=0

# Linux + AWS-LC configuration
# Major macros are explicitly defined to avoid combinatorial explosion.
# Remaining unknown macros use the default --max-configs=12 heuristic.
$CPPCHECK_EXECUTABLE --std=c99 --error-exitcode=-1 --quiet -j "$(nproc)" \
  --cppcheck-build-dir="$CPPCHECK_BUILD_DIR" \
  --enable=warning,performance,portability \
  --template='[{file}:{line}]: ({severity}:{id}) {message}' \
  --inline-suppr \
  --suppressions-list=codebuild/bin/cppcheck_suppressions.txt \
  -D__linux__ -DOPENSSL_IS_AWSLC \
  -U_WIN32 -U__FreeBSD__ -ULIBRESSL_VERSION_NUMBER -UOPENSSL_IS_BORINGSSL \
  -I . -I ./tests $DIRS || FAILED=1

if [ $FAILED == 1 ]; then
	printf "\\033[31;1mFAILED cppcheck\\033[0m\\n"
	exit -1
else
	printf "\\033[32;1mPASSED cppcheck\\033[0m\\n"
fi
