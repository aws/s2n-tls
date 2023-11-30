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
source codebuild/bin/s2n_setup_env.sh
source codebuild/bin/utils.sh

# Disable PQ
export S2N_NO_PQ=1
# Limit the number of child processes in the test run
export RUST_BACKTRACE=1
export TOX_TEST_NAME="$INTEGV2_TEST"

# There can be only one artifact config per batch job,
# so we're scipting the baseline upload steps here.
upload_artifacts(){
  cd tests/integrationv2/target/criterion
  echo "Creating zip ${AWS_S3_PATH}"
  zip -r "${AWS_S3_PATH}" ./*
  aws s3 cp "${AWS_S3_PATH}" "${AWS_S3_URL}"
  echo "S3 upload complete"
}

if [ -d "third-party-src" ]; then
  echo "Not running against c.a.c."
  return 0
fi

# setting LOCAL_TESTING disables a check for an existing baseline.
if [ -z "${LOCAL_TESTING:-}" ]; then
  # Fetch creds and the latest release number.
  gh_login s2n_codebuild_PRs
  LATEST_RELEASE_VER=$(get_latest_release)
  # Build a specific filename for this release
  AWS_S3_PATH="integv2criterion_${INTEGV2_TEST}_${LATEST_RELEASE_VER}.zip"
  zip_count=$(aws s3 ls "${AWS_S3_URL}${AWS_S3_PATH}"|wc -l||true)

  # Only do the baseline if an artifact for the current release doesn't exist.
  if [ "$zip_count" -eq 0 ]; then
    echo "File ${AWS_S3_URL}${AWS_S3_PATH} not found"
    criterion_install_deps
    ORIGINAL_COMMIT=$(git rev-parse HEAD)
    git fetch --tags
    git checkout "$LATEST_RELEASE_VER"
    S2N_USE_CRITERION=baseline make -C tests/integrationv2 "$INTEGV2_TEST"
    upload_artifacts
    git reset --hard  ${ORIGINAL_COMMIT}
  else
    echo "Found existing artifact for ${LATEST_RELEASE_VER}, not rebuilding."
    exit 0
  fi
else
  echo "Local testing enabled; baselining without checking s3"
  criterion_install_deps
  S2N_USE_CRITERION=baseline make -C tests/integrationv2 "$INTEGV2_TEST"
fi

