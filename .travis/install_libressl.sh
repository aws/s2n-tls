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
    echo "install_libressl.sh build_dir install_dir"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2

cd "$BUILD_DIR"
# Originally from: https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.6.4.tar.gz
curl https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2017-12-29_libressl-2.6.4.tar.gz > libressl-2.6.4.tar.gz
tar -xzvf libressl-2.6.4.tar.gz
cd libressl-2.6.4
./configure --prefix="$INSTALL_DIR"
make CFLAGS=-fPIC install

