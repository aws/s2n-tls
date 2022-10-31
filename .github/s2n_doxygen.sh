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
set -eu

export DOXYGEN_VERSION="doxygen-1.9.5"
curl -L "https://www.doxygen.nl/files/$DOXYGEN_VERSION.linux.bin.tar.gz" -o "$DOXYGEN_VERSION.tar.gz"
tar -xvf "$DOXYGEN_VERSION.tar.gz"

# Pull in git tags
git fetch origin --tags
curl https://raw.githubusercontent.com/jothepro/doxygen-awesome-css/main/doxygen-awesome.css -o docs/doxygen/doxygen-awesome.css

# Add a version to the Doxygen documentation
# For example: v1.3.13-3b413f18
DOC_VERSION="$(git tag --sort v:refname | tail -n 1)-$(git rev-parse --short=8 HEAD)"

sed -i "s/PROJECT_NUMBER_PLACEHOLDER/$DOC_VERSION/" docs/doxygen/Doxyfile

# We want to examine stderr for warnings
# Ignore doxygen warnings from using the README.md as the mainpage
WARNING=$($DOXYGEN_VERSION/bin/doxygen docs/doxygen/Doxyfile 2>&1 | grep -i "warning" | grep -vi "readme" )
WARNING_COUNT=$($WARNING | wc -l)

if [ $WARNING_COUNT -ne 0 ]; then
    echo $WARNING
    exit 1
else
    exit 0
fi

