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
    echo "install_python39.sh build_dir install_dir"
    exit 1
}

if [ "$#" -ne "2" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
source codebuild/bin/jobs.sh

cd "$BUILD_DIR"
curl https://www.python.org/ftp/python/3.9.10/Python-3.9.10.tgz > Python-3.9.10.tgz
tar -xzvf Python-3.9.10.tgz
cd Python-3.9.10

apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev -y
./configure --prefix="$INSTALL_DIR"
make -j $JOBS
make install

${INSTALL_DIR}/bin/python3 -m pip install tox tox-current-env pytest-xdist
