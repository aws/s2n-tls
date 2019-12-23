#!/bin/bash
# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

S2N_FILES=$(find "$PWD" -type f -name "s2n_*.[ch]")
S2N_FILES+=" "
S2N_FILES+=$(find "$PWD"/codebuild/ -type f -name "*.sh")
S2N_FILES+=" "
S2N_FILES+=$(find "$PWD"/tests/ -type f -name "*.sh")

FAILED=0

for file in $S2N_FILES; do
    # The word "Copyright" should appear at least once in the first 3 lines of every file
    COUNT=`head -3 $file | grep "Copyright" | wc -l`;
    if [ "$COUNT" == "0" ];
    then
        FAILED=1;
        echo "Copyright Check Failed: $file";
    fi
done

if [ $FAILED == 1 ];
then
    printf "\\033[31;1mFAILED Copyright Check\\033[0m\\n"
    exit -1
else
    printf "\\033[32;1mPASSED Copyright Check\\033[0m\\n"
fi
