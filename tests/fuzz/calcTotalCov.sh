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

if [[ -z "$S2N_ROOT" ]]; then
    S2N_ROOT=../..
fi

FUZZCOV_SOURCES="${S2N_ROOT}/api ${S2N_ROOT}/bin ${S2N_ROOT}/crypto ${S2N_ROOT}/error ${S2N_ROOT}/stuffer ${S2N_ROOT}/tls ${S2N_ROOT}/utils"


# Outputs fuzz coverage results if the FUZZ_COVERAGE environment variable is set
# Total coverage is overlayed on source code in s2n_cov.html and coverage statistics are available in s2n_cov.txt
# If using LLVM version 9 or greater, coverage is output in LCOV format instead of HTML
# All files are stored in the s2n coverage directory
if [[ "$FUZZ_COVERAGE" == "true" ]]; then

    printf "Calculating total s2n coverage... "

    # The llvm-profdata merge command warns that the profraws were created from different binaries (which is true) but
    # works fine for what we care about (the s2n library). Therefore, for user clarity all output is suppressed.
    llvm-profdata merge -sparse ./profiles/*/*.profdata -o ./profiles/s2n_cov.profdata > /dev/null 2>&1
    llvm-cov report -instr-profile=./profiles/s2n_cov.profdata ${S2N_ROOT}/lib/libs2n.so ${FUZZCOV_SOURCES} > ${COVERAGE_DIR}/fuzz/s2n_cov.txt

    # Use LCOV format instead of HTML if the LLVM version we're using supports it
    if [[ $(grep -Eo "[0-9]*" <<< `llvm-cov --version` | head -1) > 8 ]]; then
        llvm-cov export -instr-profile=./profiles/s2n_cov.profdata ${S2N_ROOT}/lib/libs2n.so ${FUZZCOV_SOURCES} -format=lcov > ${COVERAGE_DIR}/fuzz/s2n_cov.info
        genhtml -q -o ${COVERAGE_DIR}/html/overall_fuzz_coverage ${COVERAGE_DIR}/fuzz/s2n_cov.info
    else
        llvm-cov show -instr-profile=./profiles/s2n_cov.profdata ${S2N_ROOT}/lib/libs2n.so ${FUZZCOV_SOURCES} -use-color -format=html > ${COVERAGE_DIR}/fuzz/s2n_cov.html
    fi
    # Generate coverage report compatible with codecov.io
    llvm-cov show -instr-profile=./profiles/s2n_cov.profdata ${S2N_ROOT}/lib/libs2n.so ${FUZZCOV_SOURCES} > ${COVERAGE_DIR}/fuzz/codecov.txt

    S2N_COV=`grep -Eo '[0-9]*\.[0-9]*\%' ${COVERAGE_DIR}/fuzz/s2n_cov.txt | tail -1`
    printf "total s2n coverage from fuzz tests: %s\n" $S2N_COV
fi
