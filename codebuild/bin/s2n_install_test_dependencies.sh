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

# Install missing test dependencies. If the install directory already exists, cached artifacts will be used
# for that dependency.

if [[ ! -d test-deps ]]; then 
    mkdir test-deps ; 
fi

#Install & Run shell check before installing dependencies
echo "Installing ShellCheck..."
codebuild/bin/install_shellcheck.sh
echo "Running ShellCheck..."
find ./codebuild -type f -name '*.sh' -exec shellcheck -Cnever -s bash {} \;

# Only run ubuntu install outside of CodeBuild
if [[ "$OS_NAME" == "linux" ]]; then
    if [ ! "${CODEBUILD_BUILD_NUMBER}" ]; then
        codebuild/bin/install_ubuntu_dependencies.sh;
    fi
fi

if [[ "$OS_NAME" == "darwin" ]]; then
    codebuild/bin/install_osx_dependencies.sh;
fi

codebuild/bin/install_default_dependencies.sh

echo "Success"
