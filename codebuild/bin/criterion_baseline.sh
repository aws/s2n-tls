#!/usr/bin/env bash
set -eu
source codebuild/bin/utils.sh

AWS_S3_URL="s3://s2n-tls-logs/release/"

install_deps(){
    make install
    source "$HOME"/.cargo/env
    make -C bindings/rust
}


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
  # Don't run against c.a.c.
  return 0
fi

# Fetch creds and the latest release number.
gh_login s2n_codebuild_PRs
get_latest_release
AWS_S3_PATH="integv2criterion_${INTEGV2_TEST}_${LATEST_RELEASE_VER}.zip"

zip_count=$(aws s3 ls "${AWS_S3_URL}${AWS_S3_PATH}"|wc -l||true)
if [ "$zip_count" -eq 0 ]; then
  echo "File ${AWS_S3_URL}${AWS_S3_PATH} not found"
  install_deps
  TOX_TEST_NAME=${INTEGV2_TEST}.py make integrationv2
  upload_artifacts
else
  echo "Found existing artifact for ${LATEST_RELEASE_VER}, not rebuilding."
fi
