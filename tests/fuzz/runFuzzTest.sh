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

# The timeout command sends a TERM and under normal circumstances returns
# exit code 124. We'll undo this later. 
set -e

usage() {
    echo "Usage: runFuzzTest.sh TEST_NAME FUZZ_TIMEOUT_SEC S2N_ROOT"
    exit 1
}

if [ "$#" -ne "3" ]; then
    usage
fi

TEST_NAME=$1
FUZZ_TIMEOUT_SEC=$2
S2N_ROOT=$3

MIN_TEST_PER_SEC="1000"
MIN_FEATURES_COVERED="100"

# TEMPORARY: Force all tests to expect success to test failure upload path.
# Revert this after testing.
# if [[ $TEST_NAME == *_negative_test ]];
# then
#     EXPECTED_TEST_FAILURE=1
# else
#     EXPECTED_TEST_FAILURE=0
# fi
EXPECTED_TEST_FAILURE=0

LIBFUZZER_ARGS+="-timeout=5 -max_len=4096 -print_final_stats=1 -max_total_time=${FUZZ_TIMEOUT_SEC}"

TEST_SPECIFIC_OVERRIDES="${S2N_ROOT}/build/lib/lib${TEST_NAME}_overrides.so"
GLOBAL_OVERRIDES="${S2N_ROOT}/build/lib/libglobal_overrides.so"

FUZZCOV_SOURCES="${S2N_ROOT}/api ${S2N_ROOT}/bin ${S2N_ROOT}/crypto ${S2N_ROOT}/error ${S2N_ROOT}/stuffer ${S2N_ROOT}/tls ${S2N_ROOT}/utils"

# Use LD_PRELOAD_ to prevent symbol lookup errors in commands like mkdir.
if [ -e $TEST_SPECIFIC_OVERRIDES ];
then
    export LD_PRELOAD_="$TEST_SPECIFIC_OVERRIDES $GLOBAL_OVERRIDES"
else
    export LD_PRELOAD_="$GLOBAL_OVERRIDES"
fi

if [ ! -d "./corpus/${TEST_NAME}" ];
then
  printf "\033[33;1mWARNING!\033[0m ./corpus/${TEST_NAME} directory does not exist, feature coverage may be below minimum.\n\n"
fi

# Make directory if it doesn't exist
mkdir -p "./corpus/${TEST_NAME}"

ACTUAL_TEST_FAILURE=0

# Copy existing Corpus to a temp directory so that new inputs from fuzz tests runs will add new inputs to the temp directory.
# This allows us to minimize new inputs before merging to the original corpus directory.
TEMP_CORPUS_DIR="temp_corpus_${TEST_NAME}"
cp -r ./corpus/${TEST_NAME}/. "${TEMP_CORPUS_DIR}"

# Run fuzz test executable and store results to an output file
env LD_PRELOAD="$LD_PRELOAD_" \
LLVM_PROFILE_FILE="./profiles/${TEST_NAME}/${TEST_NAME}.%p.profraw" \
${S2N_ROOT}/build/bin/${TEST_NAME} ${LIBFUZZER_ARGS} ${TEMP_CORPUS_DIR} \
> ${TEST_NAME}_output.txt 2>&1 || ACTUAL_TEST_FAILURE=1

TEST_INFO=$(
    grep -o "stat::number_of_executed_units: [0-9]*" ${TEST_NAME}_output.txt | \
    awk -v timeout=$FUZZ_TIMEOUT_SEC '{count += int($2); rate = int(count / timeout)} END {print count, "tests, " rate " test/sec"}' \
)
TESTS_PER_SEC=$(echo "$TEST_INFO" | cut -d ' ' -f 3)
FEATURE_COVERAGE=`grep -o "ft: [0-9]*" ${TEST_NAME}_output.txt | awk '{print $2}' | sort | tail -1`

if [ $ACTUAL_TEST_FAILURE == $EXPECTED_TEST_FAILURE ];
then
    if [ $EXPECTED_TEST_FAILURE == 1 ];
    then
        # Clean up LibFuzzer corpus files if the test is negative.
        rm -f leak-* crash-*
    else
        # TEMP_CORPUS_DIR may contain many new inputs that only covers a small set of new branches. 
        # Instead of copying all new inputs to the corpus directory,  only copy back minimum number of new inputs that reach new branches.
        ${S2N_ROOT}/build/bin/${TEST_NAME} \
            -merge=1 "./corpus/${TEST_NAME}" "${TEMP_CORPUS_DIR}" \
            > ${TEST_NAME}_results.txt 2>&1

        if [ "$TESTS_PER_SEC" -lt $MIN_TEST_PER_SEC ]; then
            printf "\033[33;1mWARNING!\033[0m ${TEST_NAME} is only ${TESTS_PER_SEC} tests/sec, which is below ${MIN_TEST_PER_SEC}/sec! Fuzz tests are more effective at higher rates.\n\n"
        fi

        COVERAGE_FAILURE_ALLOWED=0
        if grep -Fxq ${TEST_NAME} ./allowed_coverage_failures.cfg
        then
            COVERAGE_FAILURE_ALLOWED=1
        fi

        if [[ "$FEATURE_COVERAGE" -lt $MIN_FEATURES_COVERED && COVERAGE_FAILURE_ALLOWED -eq 0 ]]; then
            printf "\033[31;1mERROR!\033[0m ${TEST_NAME} only covers ${FEATURE_COVERAGE} features, which is below ${MIN_FEATURES_COVERED}! This may be due to missing corpus files or a bug.\n"
            exit -1;
        fi
    fi
else
    cat ${TEST_NAME}_output.txt
    printf "\033[31;1mFAILED\033[0m %s, %6d features covered\n" "$TEST_INFO" $FEATURE_COVERAGE
    # Upload output and failure artifacts to S3 for debugging/reproduction.
    FAILURE_TIMESTAMP=$(date +%Y-%m-%d-%T)
    aws s3 cp ./${TEST_NAME}_output.txt ${ARTIFACT_UPLOAD_LOC}/${TEST_NAME}/output_${FAILURE_TIMESTAMP}.txt
    # Upload libfuzzer failure artifacts. These files contain the exact inputs that triggered the failure).
    for artifact in crash-* timeout-* leak-* oom-*; do
        [ -e "$artifact" ] && aws s3 cp "./$artifact" ${ARTIFACT_UPLOAD_LOC}/${TEST_NAME}/
    done
    exit -1
fi
