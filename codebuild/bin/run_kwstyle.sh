#! /bin/bash
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

S2N_FILES=$(find "$PWD" -type f -name "s2n_*.[ch]" | grep -v "test")

FAILED=0

for file in $S2N_FILES; do
    ERROR_LIST=$(KWStyle -gcc -v -xml codebuild/bin/KWStyle.xml "$file")
    if [ "$ERROR_LIST" != "" ] ;
    then
        echo "$ERROR_LIST"
        FAILED=1
    fi
done

if [ $FAILED == 1 ];
then
    printf "\\033[31;1mFAILED kwstyle\\033[0m\\n"
    exit -1
else
    printf "\\033[32;1mPASSED kwstyle\\033[0m\\n"
fi
