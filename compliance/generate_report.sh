#/usr/bin/env bash

set -e

TOPLEVEL=$(git rev-parse --show-toplevel)

BLOB=${1:-main}

pushd $TOPLEVEL > /dev/null

duvet \
  report \
  --spec-pattern 'compliance/specs/**/*.toml' \
  --source-pattern '(*=,*#)api/**/*.[ch]' \
  --source-pattern '(*=,*#)bin/**/*.[ch]' \
  --source-pattern '(*=,*#)crypto/**/*.[ch]' \
  --source-pattern '(*=,*#)error/**/*.[ch]' \
  --source-pattern '(*=,*#)pq-crypto/**/*.[ch]' \
  --source-pattern '(*=,*#)stuffer/**/*.[ch]' \
  --source-pattern '(*=,*#)tests/**/*.[ch]' \
  --source-pattern '(*=,*#)tls/**/*.[ch]' \
  --source-pattern '(*=,*#)utils/**/*.[ch]' \
  --require-tests false \
  --blob-link "https://github.com/aws/s2n/blob/$BLOB" \
  --issue-link 'https://github.com/aws/s2n/issues' \
  --no-cargo \
  --html compliance/report.html
  
echo "report available in compliance/report.html"

popd > /dev/null

