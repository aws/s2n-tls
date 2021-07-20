#!/usr/bin/env bash
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
set -eu

echo "Starting"
FILEPATH="${1:-"./tests/unit"}"
COMMITHASH="$(git log -1 -s --pretty=format:%h)"
COMMITDATE="$(git log -1 -s --pretty=format:%ad --date=short)"
# This can not be empty, even in the case of a detached  HEAD.
BRANCH="$(git branch --show-current)"
BRANCH="${BRANCH:-none}"
RUNDATE="$(date +%Y%m%d)"
S3BUCKET=s2n-hyperfine-data
FINALOUTPUT="$FILEPATH"/bench_"$COMMITHASH"_"$BRANCH"_"$RUNDATE".csv

csv() {
# Inject additional data into the final CSV, as we convert it from json.
# For some reason, jq wraps only strings in quotes, remove them.
echo -e "command,commithash,commitdate,mean,stddev,median,user,system,min,branch,arch\n$(jq -r \
         --arg COMMITHASH $COMMITHASH \
         --arg COMMITDATE $COMMITDATE \
         --arg BRANCH  $BRANCH \
         --arg ARCH "x86_64" \
         '.results[]|[.command, $COMMITHASH, $COMMITDATE, .mean, .stddev,.median,.user,.system,.min,$BRANCH,$ARCH]|@csv' $FILEPATH/bench_s2n*.json)" | sed 's/"//g' > $FINALOUTPUT
}



if [[ $(ls -l $FILEPATH/bench_s2n*.json|wc -l) -ge 1 ]]; then
    echo "Found bench_s2n*.json in $FILEPATH"
else
    echo "No bench_s2n json files found, exiting."
    exit 1
fi

echo -e "Injecting Vars into hyperfine data:\n\tfilepath: $FILEPATH\n\tcommithash: $COMMITHASH\n\tcommitdate: $COMMITDATE\n\tbranch: $BRANCH\n"
csv
echo "Copying to s3"
aws s3 cp $FINALOUTPUT s3://$S3BUCKET/
echo "Done"
