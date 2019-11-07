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
MIN_FEATURES_COVERED="100"

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

# Copy existing Corpus to a temp directory so that new inputs from fuzz tests runs will add new inputs to the temp directory. 
# This allows us to minimize new inputs before merging to the original corpus directory.
TEMP_CORPUS_DIR="$(mktemp -d)"
cp -r ./corpus/${TEST_NAME}/. "${TEMP_CORPUS_DIR}"


printf "Running %-s %-40s for %5d sec with %2d threads... " "${FIPS_TEST_MSG}" ${TEST_NAME} ${FUZZ_TIMEOUT_SEC} ${NUM_CPU_THREADS}
./${TEST_NAME} ${LIBFUZZER_ARGS} ${TEMP_CORPUS_DIR} > ${TEST_NAME}_output.txt 2>&1 || ACTUAL_TEST_FAILURE=1

TEST_COUNT=`grep -o "stat::number_of_executed_units: [0-9]*" ${TEST_NAME}_output.txt | awk '{test_count += $2} END {print test_count}'`
TESTS_PER_SEC=`echo $(($TEST_COUNT / $FUZZ_TIMEOUT_SEC))`
FEATURE_COVERAGE=`grep -o "ft: [0-9]*" ${TEST_NAME}_output.txt | awk '{print $2}' | sort | tail -1`

if [ $ACTUAL_TEST_FAILURE == $EXPECTED_TEST_FAILURE ];
then
    printf "\033[32;1mPASSED\033[0m %8d tests, %6d test/sec, %5d features covered" $TEST_COUNT $TESTS_PER_SEC $FEATURE_COVERAGE
    
    if [ $EXPECTED_TEST_FAILURE == 1 ];
    then
        # Clean up LibFuzzer corpus files if the test is negative.
        printf "\n"
        rm -f leak-* crash-*
    else
        # TEMP_CORPUS_DIR may contain many new inputs that only covers a small set of new branches. 
        # Instead of copying all new inputs to the corpus directory,  only copy back minimum number of new inputs that reach new branches.
        ./${TEST_NAME} -merge=1 "./corpus/${TEST_NAME}" "${TEMP_CORPUS_DIR}" > ${TEST_NAME}_results.txt 2>&1
        
        # Print number of new files and branches found in new Inputs (if any)
        RESULTS=`grep -Eo "[0-9]+ new files .*$" ${TEST_NAME}_results.txt | tail -1`
        printf ", ${RESULTS}\n"
       
        if [ "$TESTS_PER_SEC" -lt $MIN_TEST_PER_SEC ]; then
            printf "\033[33;1mWARNING!\033[0m ${TEST_NAME} is only ${TESTS_PER_SEC} tests/sec, which is below ${MIN_TEST_PER_SEC}/sec! Fuzz tests are more effective at higher rates.\n\n"
        fi

        if [ "$FEATURE_COVERAGE" -lt $MIN_FEATURES_COVERED ]; then
            printf "\033[33;1mWARNING!\033[0m ${TEST_NAME} only covers ${FEATURE_COVERAGE} features, which is below ${MIN_FEATURES_COVERED}! This is likely a bug.\n"
            exit -1;
        fi
    fi
    
else
    cat ${TEST_NAME}_output.txt
    printf "\033[31;1mFAILED\033[0m %10d tests, %6d features covered\n" $TEST_COUNT $FEATURE_COVERAGE
    exit -1
fi
