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

usage() {
    echo "install_shellcheck.sh travis_platform"
    exit 1
}

if [ "$#" -ne "1" ]; then
    usage
fi

TRAVIS_PLATFORM=$1

if [ "$TRAVIS_PLATFORM" == "linux" ]; then
    which shellcheck || (sudo apt-get -qq update && sudo apt-get -qq install shellcheck -y)
elif [ "$TRAVIS_PLATFORM" == "osx" ]; then
    # Installing an existing package is a "failure" in brew
    brew install shellcheck || true ;
else
    echo "Invalid platform! $TRAVIS_PLATFORM"
    usage
fi
