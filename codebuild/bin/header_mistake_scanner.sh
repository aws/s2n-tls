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

S2N_FILES=$(find "$PWD" -type f -name "s2n_*.[ch]")
S2N_FILES+=" "
S2N_FILES+=$(find "$PWD"/codebuild/ -type f -name "*.sh")
S2N_FILES+=" "
S2N_FILES+=$(find "$PWD"/codebuild/ -type f -name "*.yml")
S2N_FILES+=" "
S2N_FILES+=$(find "$PWD"/tests/ -type f -name "*.sh")
S2N_FILES+=" "
S2N_FILES+=$(find "$PWD"/tests/integrationv2 -type f -name "*.py")
S2N_FILES+=" "
S2N_FILES+=$(find "$PWD" -type f -name "*.rs" | grep -v target)

FAILED=0

for file in $S2N_FILES; do
    # The phrase "Copyright (20xx) Amazon.com, Inc. or its affiliates" should appear at least once in the first 4 lines of every file
    COUNT=`head -4 $file | grep -i "Copyright" | grep -i "Amazon.com, Inc. or its affiliates" | wc -l`;
    if [ "$COUNT" == "0" ];
    then
        FAILED=1;
        echo "Copyright Check Failed: $file";
    fi
done

for file in $S2N_FILES; do
    # The Apache 2.0 License should appear in every file
    COUNT=`head -5 $file | grep -E "Apache License, Version 2.0|Apache-2.0" | wc -l`;
    if [ "$COUNT" == "0" ];
    then
        FAILED=1;
        echo "License Check Failed: $file";
    fi
done

if [ $FAILED == 1 ];
then
    printf "\\033[31;1mFAILED Copyright Check\\033[0m\\n"
    exit -1
else
    printf "\\033[32;1mPASSED Copyright Check\\033[0m\\n"
fi
