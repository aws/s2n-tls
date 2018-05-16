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


set -ex

# Clear the Travis Cache Weekly to ensure that any upstream breakages in test dependencies are caught
if [[ "$TRAVIS_EVENT_TYPE" == "cron" ]]; then
    sudo rm -rf ./test-deps
fi

# Install missing test dependencies. If the install directory already exists, cached artifacts will be used
# for that dependency.

if [[ ! -d test-deps ]]; then 
    mkdir test-deps ; 
fi

#Install & Run shell check before installing dependencies
echo "Installing ShellCheck..."
.travis/install_shellcheck.sh "$TRAVIS_OS_NAME"
echo "Running ShellCheck..."
.travis/run_shellcheck.sh
echo "Shell Check is success."

if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then
    .travis/install_ubuntu_dependencies.sh;
fi

if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then 
    .travis/install_osx_dependencies.sh;
fi

.travis/install_default_dependencies.sh

echo "Success"
