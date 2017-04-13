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

brew update
brew tap homebrew/versions
brew install gcc6
brew install gnu-indent
brew install cppcheck

# Download and Install Clang Scan-build for static analysis
if [[ ! -d "$SCAN_BUILD_INSTALL_DIR" ]] && [[ "$TRAVIS_OS_NAME" == "osx" ]]; then .travis/install_scan-build.sh $SCAN_BUILD_INSTALL_DIR; fi
