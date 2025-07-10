#/usr/bin/env bash

set -e

TOPLEVEL=$(git rev-parse --show-toplevel)

BLOB=${1:-main}

pushd $TOPLEVEL > /dev/null

duvet report

popd > /dev/null
