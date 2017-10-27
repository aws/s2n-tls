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

ALL_FUZZ_TEST_FILES=""

# Disabling shellcheck warning as we won't allow spaces or glob characters in file names.
# Refer https://github.com/koalaman/shellcheck/wiki/SC2044
# shellcheck disable=SC2044
for dir in $( find ./tests/fuzz/corpus -name "s2n_*_test" -type d -exec basename {} \; ); do
    ALL_FUZZ_TEST_FILES="$ALL_FUZZ_TEST_FILES $dir"
done

echo "$ALL_FUZZ_TEST_FILES"

export FUZZ_TESTS="$ALL_FUZZ_TEST_FILES"

DONE=0
while [ $DONE -ne 1 ]; do
    make fuzz;
    NEW_CORPUS_FILES=$(git ls-files --others --exclude-standard | (grep "tests/fuzz/corpus" || echo ""))

    if [[ -n "$NEW_CORPUS_FILES" ]]; then
        file_count=0
        for file in $NEW_CORPUS_FILES; do
            printf "\\033[32;1mFound new Corpus Input:\\033[0m %s\\n" "$file"
            file_count=$((file_count+1))
            git add "$file"
        done

        FUZZ_TESTS_TO_RERUN=$(echo "$NEW_CORPUS_FILES" | awk -F'/' '{print $4}' | sort | uniq)

        export FUZZ_TESTS=""
        for test in $FUZZ_TESTS_TO_RERUN; do
            export FUZZ_TESTS="$FUZZ_TESTS $test"
        done

        printf "Found \\033[32;1m$file_count\\033[0m new corpus inputs for Fuzz Tests: %s\\n" "$FUZZ_TESTS"
    else
        printf "\\033[32;1mCorpus Maximized.\\033[0m\\n"
        DONE=1
    fi
done
