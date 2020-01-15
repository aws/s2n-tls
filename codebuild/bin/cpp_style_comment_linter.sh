#!/bin/bash
# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

S2N_FILES=$(find "$PWD" -type f -name "s2n*.[ch]")

FAILED=0

for file in $S2N_FILES; do
    # There should be no c++ style comments: //
    RESULT=`grep -rnv '\*' $file | grep '\B\/\/.*$' | grep -v '\".*\"'`;
    if [ "${#RESULT}" != "0" ];
    then
        FAILED=1;
        printf "\e[1;34mC++ Comments Check Failed in $file:\e[0m\n$RESULT\n\n";
    fi
done

if [ $FAILED == 1 ];
then
    printf "\\033[31;1mFAILED C++ Comments Check\\033[0m\\n"
    exit -1
else
    printf "\\033[32;1mPASSED C++ Comments Check\\033[0m\\n"
fi