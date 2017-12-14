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

sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y
sudo apt-get update

DEPENDENCIES="indent kwstyle"

sudo apt-get install -y ${DEPENDENCIES}

if [[ "$GCC6_REQUIRED" == "true" ]]; then
    sudo apt-get -y install gcc-6;
fi

# Download and Install prlimit for memlock
if [[ ! -d "$PRLIMIT_INSTALL_DIR" ]] && [[ "$TRAVIS_OS_NAME" == "linux" ]]; then
    mkdir -p "$PRLIMIT_INSTALL_DIR" && sudo .travis/install_prlimit.sh "$(mktemp -d)" "$PRLIMIT_INSTALL_DIR"; 
fi

if [[ "$TESTS" == "ctverif" || "$TESTS" == "ALL" ]] ; then
    .travis/install_ctverif_dependencies.sh ; fi

if [[ "$TESTS" == "ctverif" || "$TESTS" == "ALL" ]] && [[ ! -d "$CTVERIF_INSTALL_DIR" ]]; then
    mkdir -p "$CTVERIF_INSTALL_DIR" && .travis/install_ctverif.sh "$CTVERIF_INSTALL_DIR" > /dev/null ; fi

if [[ "$TESTS" == "sidewinder" || "$TESTS" == "ALL" ]] ; then
    .travis/install_sidewinder_dependencies.sh ; fi

if [[ "$TESTS" == "sidewinder" || "$TESTS" == "ALL" ]] && [[ ! -d "$SIDEWINDER_INSTALL_DIR" ]]; then
    mkdir -p "$SIDEWINDER_INSTALL_DIR" && .travis/install_sidewinder.sh "$SIDEWINDER_INSTALL_DIR" > /dev/null ; fi
