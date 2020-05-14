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

set -e
CLANG_NINE=$(which clang-format-9)
CLANG_VER=${CLANG_NINE:-clang-format}
for i in $(find . -not -path "./test-deps/*" -name '*.h' -or -name '*.c' -or -name '*.cpp'); do
        $CLANG_VER --verbose -i "$i" ;
done

if [[ `git status --porcelain` ]]; then
        echo "clang-format updated files, throwing an error"
        exit 255
else
        echo "No files touched"
fi
