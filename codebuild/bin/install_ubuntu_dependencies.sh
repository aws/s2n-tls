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

# Shim code to get local docker/ec2 instances bootstraped like a CodeBuild instance.
# Not actually used by CodeBuild.

set -eu
source ./codebuild/bin/s2n_setup_env.sh
ALTERNATIVES=""

is_supported() {
    if [[ ${DISTRO} != "ubuntu" ]]; then
        echo "Target is ubuntu; running on $DISTRO: Nothing to do."
        exit 0
    fi
    # This is prevent our sidetrails docker image from being harmed.
     if [[ ${VERSION_ID} < "16" ]]; then
        echo "Warning: Ubuntu version ${VERSION_ID} will not be updated for CI."
        exit 0
    fi
}

apt-repo-tool() {
    # This is already preinstalled on CodeBuild Docker images.
    if [[ ! -x `which add-apt-repository` ]]; then
        apt-get install -y software-properties-common
    else
        echo "Software-properties-common already installed"
    fi
}

dev9ppa() {
    echo "We need a test PPA for gcc-9, cmake,psmis on Ubuntu18"
    add-apt-repository ppa:ubuntu-toolchain-r/test -y
    add-apt-repository ppa:longsleep/golang-backports -y
    apt-get update -o Acquire::CompressionTypes::Order::=gz
    apt-get update -y
}

prlimit() {
    # If prlimit is not on our current PATH, download and compile prlimit manually. s2n needs prlimit to memlock pages
    if ! type prlimit > /dev/null && [[ ! -d "$PRLIMIT_INSTALL_DIR" ]]; then
        mkdir -p "$PRLIMIT_INSTALL_DIR";
        codebuild/bin/install_prlimit.sh "$(mktemp -d)" "$PRLIMIT_INSTALL_DIR";
    fi
    }

update_alternatives() {
    # Example: update-alternatives --install <desired path> <app/group name> <Path to versioned bin> <priority>
    # highest priority wins in auto mode
    what=${1:-none}
    if [[ "$what" =~ "clang" ]]; then
        case "$what" in
            "clang-11")
                CLANG_VERSION=11;;
            "clang-10")
                CLANG_VERSION=10;;
            "clang-9")
                CLANG_VERSION=9;;
            "clang-3.9")
                CLANG_VERSION=3.9;;
            esac
        local PRIORITY=$(echo $CLANG_VERSION|sed 's/\.//g')
        update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${CLANG_VERSION} ${PRIORITY}00
        update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${CLANG_VERSION} ${PRIORITY}00
        update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-${CLANG_VERSION} ${PRIORITY}00
        update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-${CLANG_VERSION} ${PRIORITY}00
        update-alternatives --install /usr/bin/llvm-dis llvm-dis /usr/bin/llvm-dis-${CLANG_VERSION} ${PRIORITY}00
    fi
}

# Main
is_supported
DEPENDENCIES="unzip make psmisc sudo indent iproute2 kwstyle net-tools libssl-dev tcpdump valgrind lcov m4 nettle-dev nettle-bin pkg-config gcc g++ wget zlibc zlib1g-dev python3-pip python3-testresources llvm curl git tox cmake libtool ninja-build golang-go quilt gcc g++"

if [[ -n "$GCC_VERSION" ]] && [[ "$GCC_VERSION" != "NONE" ]]; then
    DEPENDENCIES+=" gcc-$GCC_VERSION g++-$GCC_VERSION";
fi

# TODO: move install_clang call out of install_default_dependencies, for fuzzing.
if [[ "$LATEST_CLANG" != "true" ]]; then
    case "$VERSION_CODENAME" in
    "bionic")
        DEPENDENCIES+=" clang-3.9 llvm-3.9"
        ALTERNATIVES+="clang-3.9";;
    "focal")
        DEPENDENCIES+=" clang-11 llvm-11"
        ALTERNATIVES+="clang-11";;
    *)
        echo "Unclear which clang we should use for this release of Ubuntu, trying unversioned pacakge..."
        DEPENDENCIES+=" clang llvm";;
    esac
fi

apt update
apt-repo-tool
dev9ppa
prlimit
apt-get -y install --no-install-recommends ${DEPENDENCIES}
update_alternatives $ALTERNATIVES