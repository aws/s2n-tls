#!/bin/bash
# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	echo "install_libFuzzer.sh download_dir install_dir os_name"
	exit 1
}

if [ "$#" -ne "3" ]; then
	usage
fi

LIBFUZZER_DOWNLOAD_DIR=$1
LIBFUZZER_INSTALL_DIR=$2
export PLATFORM=$3

mkdir -p "$LIBFUZZER_DOWNLOAD_DIR"
cd "$LIBFUZZER_DOWNLOAD_DIR"

git clone https://chromium.googlesource.com/chromium/llvm-project/llvm/lib/Fuzzer
cd Fuzzer
git checkout 651ead
cd ..

echo "Compiling LibFuzzer..."
clang++ -c -g -v -O2 -lstdc++ -std=c++11 Fuzzer/*.cpp -IFuzzer
ar ruv libFuzzer.a Fuzzer*.o

echo "Copying libFuzzer.a to $LIBFUZZER_INSTALL_DIR"
mkdir -p "$LIBFUZZER_INSTALL_DIR"/lib && cp libFuzzer.a "$LIBFUZZER_INSTALL_DIR"/lib

