#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

set -eu

BUILDSPEC_OMNIBUS=./spec/buildspec_omnibus.yml
BUILDSPEC_FUZZ=./spec/buildspec_fuzz_batch.yml
BUILDSPEC_INTEG=./spec/buildspec_integ_batch.yml
BUILDSPEC_GENERAL=./spec/buildspec_general_batch.yml

UBUNTU="aws/codebuild/standard:4.0"
AL2="aws/codebuild/amazonlinux2-x86_64-standard:3.0"
AL2ARM="aws/codebuild/amazonlinux2-aarch64-standard:1.0"
IMAGE=$UBUNTU

synth_subjobs () {
  yq -Y -r --arg IMAGE $IMAGE '{batch:{"build-graph":[.batch."build-graph"[]| select(.identifier|contains("Fuzz")) | .env.image=$IMAGE ]}}' $BUILDSPEC_OMNIBUS > $BUILDSPEC_FUZZ
  yq -Y -r --arg IMAGE $IMAGE '{batch:{"build-graph":[.batch."build-graph"[]| select(.identifier|contains("Integ"))| .env.image=$IMAGE ]}}' $BUILDSPEC_OMNIBUS > $BUILDSPEC_INTEG
  yq -Y -r --arg IMAGE $IMAGE '{batch:{"build-graph":[.batch."build-graph"[]| select(.identifier|contains("Fuzz")|not)|select(.identifier|contains("Integ")|not)| .env.image=$IMAGE ]}}' $BUILDSPEC_OMNIBUS > $BUILDSPEC_GENERAL
}

check_buildspec () {
    OMNIBUS=$(yq -r '.batch."build-graph"|length' $BUILDSPEC_OMNIBUS)
    INTEG=$(yq -r '.batch."build-graph"|length' $BUILDSPEC_INTEG)
    FUZZ=$(yq -r '.batch."build-graph"|length' $BUILDSPEC_FUZZ)
    GENERAL=$(yq -r '.batch."build-graph"|length' $BUILDSPEC_GENERAL)
    echo -e "Checking newly created buildspec files\n$OMNIBUS = $INTEG + $FUZZ + $GENERAL"
    if (($OMNIBUS != $INTEG+$FUZZ+$GENERAL)); then
      echo "Counts do not match!"
    fi
}

usage () {
  echo "usage: $0 [OPTIONS]
    options:
        -u true         Force Codebuild docker image to be Ubuntu x86_64.
        -a true         Force Codebuild docker image to be AmazonLinux2 x86_64.
        -r true         Force Codebuild docker image to be AmazonLinux2 aarch64." 1>&2;
}

PREREQS="jq yq"
for i in $PREREQS; do
  if ! command -v $i &> /dev/null; then
     echo "$i needs to be install (use pip)"
  fi;
done
while getopts ":a:u:r:" flag; do
    case "${flag}" in
        a) export IMAGE=$AL2;;
        r) export IMAGE=$AL2ARM;;
        u) export IMAGE=$UBUNTU;;
        *) usage; exit 1;;
    esac
done

synth_subjobs
check_buildspec
echo "Note the buildspec_*_batch.yml files that were just created should only be used in-line with CodeBuild and not be commited to the repository."