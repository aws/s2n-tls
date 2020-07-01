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
	echo "install_googlebenchmark.sh download_dir install_dir os_name"
	exit 1
}

if [ "$#" -ne "3" ]; then
	usage
fi

GB_DOWNLOAD_DIR=$1
GB_INSTALL_DIR=$2
PLATFORM=$3

mkdir -p "$GB_DOWNLOAD_DIR"
cd "$GB_DOWNLOAD_DIR"

export GIT_CURL_VERBOSE=1
echo "Downloading Google Benchmark..."
git clone https://github.com/google/benchmark.git
git clone https://github.com/google/googletest.git benchmark/googletest
cd benchmark
mkdir build && cd build
cmake ../ -DCMAKE_BUILD_TYPE=Release
make

mkdir -p "$GB_INSTALL_DIR"/include && cp -rf "$GB_DOWNLOAD_DIR"/benchmark/include/benchmark "$GB_INSTALL_DIR"/include/
mkdir -p "$GB_INSTALL_DIR"/lib && cp -rf "$GB_DOWNLOAD_DIR"/benchmark/build/src/*.a "$GB_INSTALL_DIR"/lib/



