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

# upload to codecov.io
curl -Os https://uploader.codecov.io/latest/linux/codecov

echo "gonna try and upload"

chmod +x codecov
./codecov -t ${CODECOV_TOKEN} -f unit_test_coverage.info

echo "done trying the upload"
# upload to s3 (which gets mirrors to S3)
aws s3 sync coverage_report s3://s2n-tls-public-coverage-artifacts/latest

echo "done trying to write to s3"