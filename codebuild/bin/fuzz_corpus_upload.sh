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
    
    # Upload generated corpus files to the S3 bucket.
    zip -r ./tests/fuzz/corpus/${TEST_NAME}.zip ./tests/fuzz/corpus/${TEST_NAME}/ > /dev/null 2>&1
    aws s3 cp ./tests/fuzz/corpus/${TEST_NAME}.zip s3://s2n-tls-fuzz-corpus/${TEST_NAME}/corpus.zip
done

