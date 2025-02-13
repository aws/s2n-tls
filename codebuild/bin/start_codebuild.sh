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
    "Openssl3fipsWIP us-west-2 no-batch"
)

usage() {
    echo "start_codebuild.sh <source_version>"
    echo "    example: start_codebuild.sh pr/1111"
    echo "    example: start_codebuild.sh test_branch"
    echo "    example: start_codebuild.sh 1234abcd"
}

if [ "$#" -ne "1" ]; then
    usage
    # Return instead of exit so we can `source` this script
    # in order to get access to BUILDS.
    return 1
fi
SOURCE_VERSION=$1

add_command() {
    NAME=$1
    REGION=${2:-"us-west-2"}
    BATCH=${3:-"batch"}
    
    START_COMMAND="start-build-batch"
    if [ "$BATCH" = "no-batch" ]; then
        START_COMMAND="start-build"
    fi
    COMMANDS+=("aws --region $REGION codebuild $START_COMMAND --source-version $SOURCE_VERSION
        --project-name $NAME")
}

for args in "${BUILDS[@]}"; do
    add_command $args
done

echo "Builds:"
for command in "${COMMANDS[@]}"; do
    echo "$command"
done

select yn in "Start ${#COMMANDS[@]} builds" "Exit"; do
    case $REPLY in
        "1" ) echo "Starting builds..."; break;;
        "2" ) echo "No builds started."; exit;;
    esac
done

for command in "${COMMANDS[@]}"; do
    $command | grep '"id":'
done

echo "All builds successfully launched."
