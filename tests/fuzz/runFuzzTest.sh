#!/bin/bash
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

set -e

usage() {
    echo "Usage: runFuzzTest.sh TEST_NAME FUZZ_TIMEOUT_SEC"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

TEST_NAME=$1
FUZZ_TIMEOUT_SEC=$2
MIN_TEST_PER_SEC="1000"
MIN_BRANCHES_COVERED="100"

if [[ $TEST_NAME == *_negative_test ]];
then
    EXPECTED_TEST_FAILURE=1
else
    EXPECTED_TEST_FAILURE=0
fi

ASAN_OPTIONS+="symbolize=1"
LSAN_OPTIONS+="log_threads=1"
UBSAN_OPTIONS+="print_stacktrace=1"
NUM_CPU_THREADS=`nproc`
LIBFUZZER_ARGS+="-timeout=5 -max_len=4096 -print_final_stats=1 -jobs=${NUM_CPU_THREADS} -workers=${NUM_CPU_THREADS} -max_total_time=${FUZZ_TIMEOUT_SEC}"

TEST_SPECIFIC_OVERRIDES="${PWD}/LD_PRELOAD/${TEST_NAME}_overrides.so"
GLOBAL_OVERRIDES="${PWD}/LD_PRELOAD/global_overrides.so"

if [ -e $TEST_SPECIFIC_OVERRIDES ];
then
    export LD_PRELOAD="$TEST_SPECIFIC_OVERRIDES $GLOBAL_OVERRIDES"
else
    export LD_PRELOAD="$GLOBAL_OVERRIDES"
fi

FIPS_TEST_MSG=""
if [ -n "${S2N_TEST_IN_FIPS_MODE}" ];
then
    FIPS_TEST_MSG=" FIPS test"
fi

# Make directory if it doesn't exist
mkdir -p "./corpus/${TEST_NAME}"

ACTUAL_TEST_FAILURE=0
CORPUS_DIR="./corpus/${TEST_NAME}"
printf "Running %-s %-40s for %5d sec with %2d threads... " "${FIPS_TEST_MSG}" ${TEST_NAME} ${FUZZ_TIMEOUT_SEC} ${NUM_CPU_THREADS}
./${TEST_NAME} ${LIBFUZZER_ARGS} ${CORPUS_DIR} > ${TEST_NAME}_output.txt 2>&1 || ACTUAL_TEST_FAILURE=1

TEST_COUNT=`grep -o "stat::number_of_executed_units: [0-9]*" ${TEST_NAME}_output.txt | awk '{test_count += $2} END {print test_count}'`
TESTS_PER_SEC=`echo $(($TEST_COUNT / $FUZZ_TIMEOUT_SEC))`
BRANCH_COVERAGE=`grep -o "cov: [0-9]*" ${TEST_NAME}_output.txt | awk '{print $2}' | sort | tail -1`

if [ $ACTUAL_TEST_FAILURE == $EXPECTED_TEST_FAILURE ];
then
    printf "\033[32;1mPASSED\033[0m %8d tests, %6d test/sec, %5d branches covered\n" $TEST_COUNT $TESTS_PER_SEC $BRANCH_COVERAGE
    
    if [ $EXPECTED_TEST_FAILURE == 1 ];
    then
        # Clean up LibFuzzer corpus files if the test is negative.
        rm -f leak-* crash-*
    else
        if [ "$MINIMIZE_FUZZ_CORPUS" == "1" ];
        then
            # Make temp dir and move all corpus files to it
            tmpdir="$(mktemp -d)"
            mv "${CORPUS_DIR}"/* "$tmpdir"
            
            # Move back minimum number of files that cover all branches
            ./${TEST_NAME} -merge=1 "${CORPUS_DIR}" "$tmpdir"
        fi
        
        if [ "$TESTS_PER_SEC" -lt $MIN_TEST_PER_SEC ]; then
            printf "\033[33;1mWARNING!\033[0m ${TEST_NAME} is only ${TESTS_PER_SEC} tests/sec, which is below ${MIN_TEST_PER_SEC}/sec! Fuzz tests are more effective at higher rates.\n\n"
        fi

        if [ "$BRANCH_COVERAGE" -lt $MIN_BRANCHES_COVERED ]; then
            printf "\033[33;1mWARNING!\033[0m ${TEST_NAME} only covers ${BRANCH_COVERAGE} branches, which is below ${MIN_BRANCHES_COVERED} branches! This is likely a bug.\n"
            exit -1;
        fi
    fi
    
else
    cat ${TEST_NAME}_output.txt
    printf "\033[31;1mFAILED\033[0m %10d tests, %6d branches covered\n" $TEST_COUNT $BRANCH_COVERAGE
    exit -1
fi
