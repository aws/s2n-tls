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
set -eu
source ./codebuild/bin/utils.sh
# Disable PQ
export S2N_NO_PQ=1
export AWS_S3_BUCKET="s3://s2n-tls-logs/"
# Limit the number of child processes in the test run
export RUST_BACKTRACE=1

export GIT_COMMIT=$(git log -n 1 --format="%h")
export AWS_S3_REPORT_PATH="reports/${INTEGV2_TEST}/$(date +%Y%m%d_%H%M_${GIT_COMMIT})"

# CodeBuild artifacts are too limited;
# scipting the baseline download steps here.
download_artifacts(){
  mkdir -p ./tests/integrationv2/target/criterion || true
  echo "Downloading ${AWS_S3_BUCKET}${1}/${2}"
  pushd  ./tests/integrationv2/target/criterion/
  aws s3 cp "${AWS_S3_BUCKET}${1}/${2}" .
  unzip -o "${2}"
  echo "S3 download complete"
  popd
}

upload_report(){
  cd tests/integrationv2/target/criterion
  echo "Uploading report to ${AWS_S3_BUCKET}/${AWS_S3_REPORT_PATH}"
  aws s3 sync . "${AWS_S3_BUCKET}${AWS_S3_REPORT_PATH}"
  echo "S3 upload complete"
}

# Fetch creds and the latest release number.
gh_login s2n_codebuild_PRs
LATEST_RELEASE_VER=$(get_latest_release)
AWS_ZIPFILE="integv2criterion_${INTEGV2_TEST}_${LATEST_RELEASE_VER}.zip"
AWS_S3_BASE_PATH="release"
criterion_install_deps
download_artifacts ${AWS_S3_BASE_PATH} ${AWS_ZIPFILE}

echo "Current dir: $(pwd)"
S2N_USE_CRITERION=delta make -C tests/integrationv2 "$INTEGV2_TEST"
upload_report

