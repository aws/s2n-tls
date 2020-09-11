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
source codebuild/bin/s2n_setup_env.sh

# Install missing test dependencies. If the install directory already exists, cached artifacts will be used
# for that dependency.

if [[ ! -d test-deps ]]; then
    mkdir test-deps ;
fi

# Are we running on CodeBuild?
CODEBUILD=${CODEBUILD_BUILD_NUMBER:-}

#Install shell check
echo "Installing ShellCheck..."
codebuild/bin/install_shellcheck.sh

if [[ "$OS_NAME" == "linux" ]]; then
    # Only run ubuntu install outside of CodeBuild
    if [[ ! -z "${CODEBUILD}" && "$DISTO"=="Ubuntu" ]]; then
	    if [[ "$ARCH" == "x86_64" ]]; then
        	codebuild/bin/install_ubuntu_dependencies.sh;
	    fi
    fi
fi

if [[ "$OS_NAME" == "darwin" ]]; then
    codebuild/bin/install_osx_dependencies.sh;
fi

codebuild/bin/install_default_dependencies.sh

echo "Success"
