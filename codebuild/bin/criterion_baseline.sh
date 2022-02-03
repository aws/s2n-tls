#!/usr/bin/env bash
set -eux
AWS_S3_URL="s3://s2n-tls-logs/main"
source codebuild/bin/utils.sh

install_deps(){
    make install
    . $HOME/.cargo/env
    make -C bindings/rust
}


if [ -d "third-party-src" ]; then
  # Don't run against c.a.c.
  return 0
fi
gh_login s2n_codebuild_PRs
get_latest_release
zip_count=$(aws s3 ls ${S3_FULLPATH}|wc -l||true)
if [ "$zip_count" -eq 0 ]; then
  install_deps
  TOX_TEST_NAME=$INTEGV2_TEST.py make integrationv2
else
  echo "Found existing artifact for $RELEASE_VER, not rebuilding."
fi
