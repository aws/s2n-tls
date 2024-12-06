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

FUZZCOV_SOURCES="api bin crypto error stuffer tls utils"

printf "Calculating total s2n coverage... "

# The llvm-profdata merge command warns that the profraws were created from different binaries (which is true) but
# works fine for what we care about (the s2n library). Therefore, for user clarity all output is suppressed.
llvm-profdata merge -sparse tests/fuzz/profiles/*/*.profdata -o tests/fuzz/profiles/merged_fuzz.profdata > /dev/null 2>&1

llvm-cov report -instr-profile=tests/fuzz/profiles/merged_fuzz.profdata build/lib/libs2n.so ${FUZZCOV_SOURCES} > s2n_fuzz_coverage.txt

# convert coverage information to html format
llvm-cov export -instr-profile=tests/fuzz/profiles/merged_fuzz.profdata build/lib/libs2n.so ${FUZZCOV_SOURCES} -format=lcov > s2n_fuzz_cov.info

genhtml s2n_fuzz_cov.info --branch-coverage -q -o fuzz_coverage_report

S2N_COV=`grep -Eo '[0-9]*\.[0-9]*\%' s2n_fuzz_coverage.txt | tail -1`
printf "total s2n coverage from fuzz tests: %s\n" $S2N_COV
