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

# Get a list of changed files
REMOTE="${1:-origin}"
BRANCH="${2:-main}"
changed_files=$(git diff "$REMOTE"/"$BRANCH" --name-only )

# Run clang-format on each changed file
for file in $changed_files
do
    if [[ $file == *.c || $file == *.h ]]; then # Only run on .c and .h files
        echo "clang formatting ${file}"
        clang-format -i $file
    fi
done
