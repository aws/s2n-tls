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


set -xe

usage() {
	echo "install_saw.sh download_dir install_dir"
	exit 1
}

if [ "$#" -ne "2" ]; then
	usage
fi

DOWNLOAD_DIR=$1
INSTALL_DIR=$2

mkdir -p "$DOWNLOAD_DIR"
cd "$DOWNLOAD_DIR"

#download saw binaries
curl --retry 3 https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/saw-0.4.0.99-2019-12-10-Ubuntu14.04-64.tar.gz --output saw.tar.gz

mkdir -p saw && tar -xzf saw.tar.gz --strip-components=1 -C saw
mkdir -p "$INSTALL_DIR" && mv saw/* "$INSTALL_DIR"

"$INSTALL_DIR"/bin/saw --version
