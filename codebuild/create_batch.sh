#!/usr/bin/env bash
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

OMNIBUSCHANGED=0
FUZZCHANGED=0
INTEGCHANGED=0
GENERALCHANGED=0

synth_subjobs () {
  yq -S -Y -r '{batch:{"build-list":[.batch."build-list"[]| select(.identifier|contains("Fuzz")) ]}}' $BUILDSPEC_OMNIBUS > $BUILDSPEC_FUZZ
  yq -S -Y -r '{batch:{"build-list":[.batch."build-list"[]| select(.identifier|contains("Integ")) ]}}' $BUILDSPEC_OMNIBUS > $BUILDSPEC_INTEG
  yq -S -Y -r '{batch:{"build-list":[.batch."build-list"[]| select(.identifier|contains("Fuzz")|not)|select(.identifier|contains("Integ")|not) ]}}' $BUILDSPEC_OMNIBUS > $BUILDSPEC_GENERAL
}


check_buildspec () {
    OMNIBUS=$(yq -r '.batch."build-list"|length' $BUILDSPEC_OMNIBUS)
    INTEG=$(yq -r '.batch."build-list"|length' $BUILDSPEC_INTEG)
    FUZZ=$(yq -r '.batch."build-list"|length' $BUILDSPEC_FUZZ)
    GENERAL=$(yq -r '.batch."build-list"|length' $BUILDSPEC_GENERAL)
    echo -e "Checking newly created buildspec files\n$OMNIBUS = $INTEG + $FUZZ + $GENERAL"
    if (($OMNIBUS != $INTEG+$FUZZ+$GENERAL)); then
      echo "Counts do not match!"
    fi
}

download_cb_source () {
  for job in s2nFuzzBatch s2nGeneralBatch s2nIntegrationBatch s2nOmnibus; do
    echo "Downloading spec files for $job"
    aws codebuild batch-get-projects --name $job|jq -r '.projects[].source' > "$job"_source.json
    jq -r '.buildspec' "$job"_source.json > buildspec_"$job"_current.yml
  done
}

upload_cb_source () {
    local NEWBUILDSPEC=$1
    local jobname=$2
    local jobsource="$jobname"_source.json
    echo "Merging buildspec into .source json"
    jq -r --arg NEWBUILDSPEC "$(cat $NEWBUILDSPEC)" '.buildspec=$NEWBUILDSPEC' "$jobsource" > "$jobname"_new.json
    echo "Not updating live buildspecs...yet"
    #echo "Uploading new CodeBuild buildspec for $jobname"
    #aws codebuild update-project --name "$jobname" --source="$(cat "$jobname"_new.json)"
}

check_drift(){
  local current=$1
  local new=$2
  echo -e "\n====\nChanges for $new\n===="
  set +e
  diff -B "$current" "$new"
  return "$?"
}

PREREQS="jq yq"
for i in $PREREQS; do
  if ! command -v $i &> /dev/null; then
     echo "$i needs to be install (use pip)"
  fi;
done
synth_subjobs
check_buildspec
download_cb_source

check_drift "buildspec_s2nOmnibus_current.yml" "$BUILDSPEC_OMNIBUS"
OMNIBUSCHANGED="$?"
check_drift "buildspec_s2nFuzzBatch_current.yml" "$BUILDSPEC_FUZZ"
FUZZCHANGED="$?"
check_drift "buildspec_s2nIntegrationBatch_current.yml" $BUILDSPEC_INTEG
INTEGCHANGED="$?"
check_drift "buildspec_s2nGeneralBatch_current.yml" $BUILDSPEC_GENERAL
GENERALCHANGED="$?"

echo -e "Status of drift\nOmnibus: $OMNIBUSCHANGED\nFuzz: $FUZZCHANGED\nInteg:$INTEGCHANGED\nGeneral:$GENERALCHANGED\n"
set -e

if [[ "$OMNIBUSCHANGED" == "0" ]]; then
  echo "No changes, exiting"
  exit 0
fi

echo "Proceed with update? (enter)"
read
#upload_cb_source $BUILDSPEC_OMNIBUS s2nOmnibus
rm *_current.yml *_source.json *_new.json
echo "Done."