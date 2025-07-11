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

# Codebuild does not run in the Github CI if certain files are modified.
# Launching each individual build from the Codebuild UI is slow and tedious.
# Instead, this script will launch all the Codebuild builds at once.
# You will need to setup the AWS CLI with the proper authentication.

set -e

BUILDS=(
    "AddressSanitizer"
    "S2nIntegrationV2SmallBatch"
    "Valgrind"
    "s2nFuzzBatch"
    "s2nGeneralBatch"
    "s2nUnitNix"
    "Integv2NixBatchBF1FB83F-7tcZOiMDWPH0 us-east-2 batch"
    "kTLS us-west-2 no-batch"
)

usage() {
    echo "start_codebuild.sh <source_version> <repo>"
    echo "    example: start_codebuild.sh pr/1111"
    echo "    example: start_codebuild.sh 1234abcd"
    echo "    example: start_codebuild.sh test_branch lrstewart/s2n"
}

if [ "$#" -lt "1" ]; then
    usage
    exit 1
fi
SOURCE_VERSION=$1
REPO=${2:-aws/s2n-tls}

start_build() {
    NAME=$1
    REGION=${2:-"us-west-2"}
    BATCH=${3:-"batch"}
    
    START_COMMAND="start-build-batch"
    if [ "$BATCH" = "no-batch" ]; then
        START_COMMAND="start-build"
    fi
    aws --region $REGION codebuild $START_COMMAND \
        --project-name $NAME \
        --source-location-override https://github.com/$REPO \
        --source-version $SOURCE_VERSION | jq -re "(.buildBatch.id // .build.id)"
}

for args in "${BUILDS[@]}"; do
    start_build $args
done
echo "All builds successfully started."
