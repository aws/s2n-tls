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
set -ex

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

# Run AFL instead of libfuzzer if AFL_FUZZ is set. Not compatible with fuzz coverage.
if [[ "$AFL_FUZZ" == "true" && "$FUZZ_COVERAGE" != "true" ]]; then
	# Clusterfuzz's bash script changed from AFL to AFL++ on April 1, 2021; this
	# commit (ac5ac9e4604ea03cfd643185ad1e3800e952ea44) pins the script to an older version
	# of Clusterfuzz until we support AFL++.
	mkdir -p "$LIBFUZZER_INSTALL_DIR" && curl https://raw.githubusercontent.com/google/clusterfuzz/ac5ac9e4604ea03cfd643185ad1e3800e952ea44/docs/setting-up-fuzzing/build_afl.bash > "$LIBFUZZER_INSTALL_DIR"/build_afl.bash
	chmod +x "$LIBFUZZER_INSTALL_DIR"/build_afl.bash
	cd "$LIBFUZZER_INSTALL_DIR"
	"$LIBFUZZER_INSTALL_DIR"/build_afl.bash
	cd -
fi
