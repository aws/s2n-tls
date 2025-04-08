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

for FUZZ_TEST in tests/fuzz/*.c; do
    # extract file name without extension
    TEST_NAME=$(basename "$FUZZ_TEST")
    TEST_NAME="${TEST_NAME%.*}"
    
    # temp corpus folder to store downloaded corpus files
    TEMP_CORPUS_DIR="./tests/fuzz/temp_corpus_${TEST_NAME}"

    # Check if corpus.zip exists in the specified S3 location.
    # `> /dev/null 2>&1` redirects output to /dev/null.
    # If the file is not found, `aws s3 ls` returns a non-zero exit code.
    if aws s3 ls "s3://s2n-tls-fuzz-corpus/${TEST_NAME}/corpus.zip" > /dev/null 2>&1; then
        aws s3 cp "s3://s2n-tls-fuzz-corpus/${TEST_NAME}/corpus.zip" "${TEMP_CORPUS_DIR}/corpus.zip"
        unzip -o "${TEMP_CORPUS_DIR}/corpus.zip" -d "${TEMP_CORPUS_DIR}" > /dev/null 2>&1
    else
        printf "corpus.zip not found for ${TEST_NAME}"
    fi
done
