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
	echo "install_z3_yices.sh download_dir install_dir"
	exit 1
}

if [ "$#" -ne "2" ]; then
	usage
fi

DOWNLOAD_DIR=$1
INSTALL_DIR=$2

mkdir -p "$DOWNLOAD_DIR"
cd "$DOWNLOAD_DIR"

#download z3 and yices
curl --retry 3 https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/yices-2.6.1-x86_64-pc-linux-gnu-static-gmp.tar.gz --output yices.tar.gz
tar -xf yices.tar.gz

curl --retry 3 https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/z3-2017-04-04-Ubuntu14.04-64 --output z3

mkdir -p "$INSTALL_DIR"/bin
mv z3 "$INSTALL_DIR"/bin
mv yices-2.6.1/bin/* "$INSTALL_DIR"/bin
sudo chmod +x  "$INSTALL_DIR"/bin/*

"$INSTALL_DIR"/bin/yices-smt2 --version
"$INSTALL_DIR"/bin/yices --version
"$INSTALL_DIR"/bin/z3 --version
