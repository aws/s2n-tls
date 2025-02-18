#!/usr/bin/env bash
set -eu

usage() {
    echo "$0 build_dir install_dir"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

CBPATH=$(dirname $0)
BUILD_DIR=$1
INSTALL_DIR=$2

$CBPATH/install_awslc_fips.sh $BUILD_DIR $INSTALL_DIR 2024