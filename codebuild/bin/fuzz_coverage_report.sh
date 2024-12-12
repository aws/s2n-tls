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

usage() {
    echo "Usage: calcTotalCov.sh"
    exit 1
}

if [ "$#" -ne "0" ]; then
    usage
fi

FUZZ_TEST_DIR="tests/fuzz"
FUZZCOV_SOURCES="api bin crypto error stuffer tls utils"

# generate coverage report for each fuzz test
printf "Generating coverage reports... \n"

mkdir -p coverage/fuzz
for FUZZ_TEST in "$FUZZ_TEST_DIR"/*.c; do
    # extract file name without extension
    TEST_NAME=$(basename "$FUZZ_TEST")
    TEST_NAME="${TEST_NAME%.*}"

    # merge multiple .profraw files into a single .profdata file
    llvm-profdata merge \
        -sparse tests/fuzz/profiles/${TEST_NAME}/*.profraw \
        -o tests/fuzz/profiles/${TEST_NAME}/${TEST_NAME}.profdata

    # generate a coverage report in text format
    llvm-cov report \
        -instr-profile=tests/fuzz/profiles/${TEST_NAME}/${TEST_NAME}.profdata build/lib/libs2n.so ${FUZZCOV_SOURCES} \
        -show-functions \
        > coverage/fuzz/${TEST_NAME}_cov.txt

    # exports coverage data in LCOV format
    llvm-cov export \
        -instr-profile=tests/fuzz/profiles/${TEST_NAME}/${TEST_NAME}.profdata build/lib/libs2n.so ${FUZZCOV_SOURCES} \
        -format=lcov \
        > coverage/fuzz/${TEST_NAME}_cov.info

    # convert to HTML format
    genhtml -q -o coverage/html/${TEST_NAME} coverage/fuzz/${TEST_NAME}_cov.info > /dev/null 2>&1
done

# merge all coverage reports into a single report that shows total s2n coverage
printf "Calculating total s2n coverage... \n"
llvm-profdata merge \
    -sparse tests/fuzz/profiles/*/*.profdata \
    -o tests/fuzz/profiles/merged_fuzz.profdata

llvm-cov report \
    -instr-profile=tests/fuzz/profiles/merged_fuzz.profdata build/lib/libs2n.so ${FUZZCOV_SOURCES} \
    > s2n_fuzz_coverage.txt

llvm-cov export \
    -instr-profile=tests/fuzz/profiles/merged_fuzz.profdata build/lib/libs2n.so ${FUZZCOV_SOURCES} \
    -format=lcov \
    > s2n_fuzz_cov.info
    
genhtml s2n_fuzz_cov.info --branch-coverage -q -o coverage/fuzz/total_fuzz_coverage
