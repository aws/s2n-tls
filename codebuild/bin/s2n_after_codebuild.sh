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

set -ex

# Upload Code Coverage Information to CodeCov.io
if [[ "$CODECOV_IO_UPLOAD" == "true" ]]; then
    # Evaluate more coverage options and re-renable
    # https://github.com/aws/s2n-tls/issues/2349
    echo "Skipping coverage upload"
    if [[ "$FUZZ_COVERAGE" == "true" ]]; then
        echo "Skipping fuzz upload"
        # bash <(curl -s https://codecov.io/bash) -f coverage/fuzz/codecov.txt -F ${TESTS};
    else
        echo "Skipping test upload"
        # bash <(curl -s https://codecov.io/bash) -F ${TESTS};
    fi
fi

