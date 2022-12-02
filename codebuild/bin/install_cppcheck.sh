#!/bin/bash
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
#

set -e

usage() {
    echo "install_cppcheck.sh install_dir"
    exit 1
}

if [ "$#" -ne "1" ]; then
    usage
fi

INSTALL_DIR=$1
source codebuild/bin/jobs.sh

mkdir -p $INSTALL_DIR||true
cd "$INSTALL_DIR"
git clone --branch 2.3 --depth 1 https://github.com/danmar/cppcheck.git cppcheck-src
cd cppcheck-src

make -j $JOBS

mv cppcheck ..
mv cfg ..
cd ..
rm -rf cppcheck-src
