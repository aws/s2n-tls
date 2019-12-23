#!/bin/bash
#
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

set -e
source codebuild/bin/s2n_setup_env.sh

if [ -f "/etc/lsb-release" ]; then
    source /etc/lsb-release
fi

usage() {
    echo "install_shellcheck.sh"
    exit 1
}

if [ "$#" -ne "0" ]; then
    usage
fi

if [ "$OS_NAME" == "linux" ]; then
    which shellcheck || (sudo apt-get -qq update && sudo apt-get -qq install shellcheck -y)
elif [ "$OS_NAME" == "darwin" ]; then
    # Installing an existing package is a "failure" in brew
    brew install shellcheck || true ;
else
    echo "Invalid platform! $OS_NAME"
    usage
fi
