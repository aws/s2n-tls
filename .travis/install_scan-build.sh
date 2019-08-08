#!/bin/bash
# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

set -e

usage() {
    echo "install_scan-build.sh install_dir"
    exit 1
}

if [ "$#" -ne "1" ]; then
    usage
fi
INSTALL_DIR=$1
# Originally from: http://clang-analyzer.llvm.org/downloads/checker-278.tar.bz2
curl --retry 3 https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2017-08-29_clang-analyzer_checker.tar.bz2 --output checker-278.tar.bz2
mkdir -p "$INSTALL_DIR" && tar jxf checker-278.tar.bz2 --strip-components=1 -C "$INSTALL_DIR"
