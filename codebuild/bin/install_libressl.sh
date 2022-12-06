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
    echo "install_libressl.sh build_dir install_dir"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
source codebuild/bin/jobs.sh

cd "$BUILD_DIR"
# Originally from https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.4.3.tar.gz
curl https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2022-12-01_libressl-3.6.1.tar.gz > libressl-3.6.1.tar.gz
tar -xzvf libressl-3.6.1.tar.gz
cd libressl-3.6.1
./configure --prefix="$INSTALL_DIR"
make -j $JOBS CFLAGS=-fPIC install
