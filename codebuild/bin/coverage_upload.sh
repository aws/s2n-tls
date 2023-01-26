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
echo "The codebuild source version is ${CODEBUILD_SOURCE_VERSION}"

CLOUDFRONT_DISTRIBUTION="https://dx1inn44oyl7n.cloudfront.net"

aws s3 sync coverage_report      s3://s2n-tls-public-coverage-artifacts/${CODEBUILD_SOURCE_VERSION}/report
aws s3 cp   coverage_summary.txt s3://s2n-tls-public-coverage-artifacts/${CODEBUILD_SOURCE_VERSION}/summary.txt

echo "report : is at ${CLOUDFRONT_DISTRIBUTION}/${CODEBUILD_SOURCE_VERSION}/report/index.html"
echo "summary: is at ${CLOUDFRONT_DISTRIBUTION}/${CODEBUILD_SOURCE_VERSION}/summary.txt"
