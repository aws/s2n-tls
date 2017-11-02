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

make indent > /dev/null
DIFF_LINE_COUNT=$(git diff | wc -l)

if [ "$DIFF_LINE_COUNT" != 0 ]; then
	git diff
	printf "\033[31;1mFAILED check_indent\033[0m\n"
	exit -1
else
	printf "\033[32;1mPASSED check_indent\033[0m\n"
fi