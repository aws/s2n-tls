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
	echo "install_clang.sh download_dir install_dir os_name"
	exit 1
}

if [ "$#" -ne "3" ]; then
	usage
fi

CLANG_DOWNLOAD_DIR=$1
CLANG_INSTALL_DIR=$2
PLATFORM=$3

mkdir -p "$CLANG_DOWNLOAD_DIR"
cd "$CLANG_DOWNLOAD_DIR"

if [ "$PLATFORM" == "linux" ]; then
	# The Certificate used by chromium.googlesource.com is not in the default CA
	# list supported by git/curl on Ubuntu, but the certificate is in the
	# ca-certificates.crt file in Ubuntu, so set this env variable so that it is
	# picked up by git.
	export SSL_CERT_FILE=/usr/lib/ssl/certs/ca-certificates.crt
fi

export GIT_CURL_VERBOSE=1
echo "Downloading Clang..."
git clone https://chromium.googlesource.com/chromium/src/tools/clang

echo "Updating Clang..."
python3 "$CLANG_DOWNLOAD_DIR"/clang/scripts/update.py

# "third_party" directory is created above $CLANG_DOWNLOAD_DIR after running 
# update, move it into $CLANG_DOWNLOAD_DIR once update is complete.
mv ../third_party "$CLANG_DOWNLOAD_DIR"

echo "Installed Clang Version: "
"$CLANG_DOWNLOAD_DIR"/third_party/llvm-build/Release+Asserts/bin/clang --version

mkdir -p "$CLANG_INSTALL_DIR" && cp -rf "$CLANG_DOWNLOAD_DIR"/third_party/llvm-build/Release+Asserts/* "$CLANG_INSTALL_DIR"

