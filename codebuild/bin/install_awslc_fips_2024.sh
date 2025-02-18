#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
set -eu

usage() {
    echo "$0 build_dir install_dir"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

CBPATH=$(dirname $0)

$CBPATH/install_awslc_fips.sh $@ 2024