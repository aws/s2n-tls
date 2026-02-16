#!/usr/bin/env bash
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

# Checks C/C++ files for clang-format conformance.
# Usage: ./run_clang_format.sh

set -eo pipefail

CLANG_FORMAT_VERSION="18"
INCLUDE_REGEX='^(\.\/)?(api|bin|crypto|stuffer|error|tls|utils|tests\/unit|tests\/testlib|docs\/examples).*\.(c|h)$'
FALLBACK_STYLE="llvm"

# Install clang-format
wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo add-apt-repository -y "deb http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-${CLANG_FORMAT_VERSION} main"
sudo apt-get update
sudo apt-get install -y clang-format-${CLANG_FORMAT_VERSION}

# Print version
clang-format-${CLANG_FORMAT_VERSION} --version

exit_code=0

# Find all matching source files
src_files=$(find . -name .git -prune -o -regextype posix-egrep -regex "$INCLUDE_REGEX" -print)

IFS=$'\n'
for file in $src_files; do
  if ! clang-format-${CLANG_FORMAT_VERSION} --dry-run --Werror --style=file --fallback-style="$FALLBACK_STYLE" "$file"; then
    echo "Failed on file: $file" >&2
    echo "* \`$file\`" >> failing-files.txt
    exit_code=1
  fi
done

if [[ $exit_code -ne 0 ]] && [[ -f failing-files.txt ]]; then
  echo ""
  echo "The following files have formatting issues:"
  cat failing-files.txt
fi

exit "$exit_code"
