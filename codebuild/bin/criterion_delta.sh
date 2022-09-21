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
export S2N_NOPQ=1
export AWS_S3_URL="s3://s2n-tls-logs/release/"
# Limit the number of child processes in the test run
export XDIST_WORKERS=2
export RUST_BACKTRACE=1


# CodeBuild artifacts are too limited;
# scipting the baseline download steps here.
download_artifacts(){
  mkdir -p ./tests/integrationv2/target/criterion || true
  echo "Downloadingp ${AWS_S3_URL}${AWS_S3_PATH}"
  pushd  ./tests/integrationv2/target/criterion/
  aws s3 cp ${AWS_S3_URL}${AWS_S3_PATH} .
  unzip -o ${AWS_S3_PATH}
  echo "S3 download complete"
  popd
}

# Fetch creds and the latest release number.
gh_login s2n_codebuild_PRs
get_latest_release
AWS_S3_PATH="integv2criterion_${INTEGV2_TEST}_${LATEST_RELEASE_VER}.zip"
criterion_install_deps
download_artifacts

echo "Current dir: $(pwd)"
S2N_USECRITERION=delta make -C tests/integrationv2 "$INTEGV2_TEST"
S2N_USECRITERION=report make -C tests/integrationv2 "$INTEGV2_TEST"
