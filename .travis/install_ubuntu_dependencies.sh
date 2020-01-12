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

apt-key list
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 6B05F25D762E3157
apt-key list

sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y
sudo apt-get update -o Acquire::CompressionTypes::Order::=gz

DEPENDENCIES="unzip make indent kwstyle libssl-dev tcpdump valgrind lcov m4 nettle-dev nettle-bin pkg-config gcc g++ zlibc zlib1g-dev python3-pip llvm"

sudo apt-get install -y ${DEPENDENCIES}

if [[ -n "$GCC_VERSION" ]] && [[ "$GCC_VERSION" != "NONE" ]]; then
    sudo apt-get -y install gcc-$GCC_VERSION g++-$GCC_VERSION;
fi

# If prlimit is not on our current PATH, download and compile prlimit manually. s2n needs prlimit to memlock pages
if ! type prlimit > /dev/null && [[ ! -d "$PRLIMIT_INSTALL_DIR" ]]; then
    mkdir -p "$PRLIMIT_INSTALL_DIR";
    sudo .travis/install_prlimit.sh "$(mktemp -d)" "$PRLIMIT_INSTALL_DIR";
fi

if [[ "$TESTS" == "ctverif" || "$TESTS" == "ALL" ]] ; then
    .travis/install_ctverif_dependencies.sh ; fi

if [[ "$TESTS" == "ctverif" || "$TESTS" == "ALL" ]] && [[ ! -d "$CTVERIF_INSTALL_DIR" ]]; then
    mkdir -p "$CTVERIF_INSTALL_DIR" && .travis/install_ctverif.sh "$CTVERIF_INSTALL_DIR" > /dev/null ; fi

if [[ "$TESTS" == "sidetrail" || "$TESTS" == "ALL" ]] ; then
    .travis/install_sidetrail_dependencies.sh ; fi

if [[ "$TESTS" == "sidetrail" || "$TESTS" == "ALL" ]] && [[ ! -d "$SIDETRAIL_INSTALL_DIR" ]]; then
    mkdir -p "$SIDETRAIL_INSTALL_DIR" && .travis/install_sidetrail.sh "$SIDETRAIL_INSTALL_DIR" > /dev/null ; fi
