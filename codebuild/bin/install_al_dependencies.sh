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
source ./codebuild/bin/s2n_setup_env.sh

al2023_main(){
    case "$S2N_LIBCRYPTO" in
    "default") echo "Using default system libcrypto";;
    *) echo "${S2N_LIBCRYPTO} is not installed on this platform."; exit 1;;
    esac
    common_packages
    al2023_packages
    versions
}

al2_main() {
    echo "Installing AL2 packages"
    common_packages
    al2_packages
    symlink_all_the_things

    case "$S2N_LIBCRYPTO" in
    "openssl-1.1.1")
        yum erase -y openssl-devel || true
        yum install -y openssl11-static openssl11-libs openssl11-devel
        ;;
    "default") echo "Using default system libcrypto";;
    *) echo "Unknown libcrypto: ${S2N_LIBCRYPTO}"; exit 1;;
    esac
    versions
}

common_packages(){
    # Borrowed from https://github.com/aws/aws-codebuild-docker-images/blob/master/al2/x86_64/standard/5.0/Dockerfile#L24
    mono
    yum groupinstall -y "Development tools"
    yum install -y clang git cmake3 iproute net-tools nettle-devel nettle which sudo psmisc
    yum install -y python3-pip tcpdump unzip zlib-devel libtool ninja-build valgrind wget
    rm /etc/yum.repos.d/mono-centos7-stable.repo
}

al2023_packages(){
    # Openssl 3.0 headers and go
    yum install -y openssl-devel golang
    # TODO: cmake isn't finding awslc https://github.com/aws/s2n-tls/issues/4633
    #./codebuild/bin/install_awslc.sh $(mktemp -d) /usr/local/awsc 0
}

al2_packages() {
    # Latest AL2 image had dependency issues related to NodeJS.
    # We don't use NodeJS, so just remove it.
    yum erase -y nodejs || true
    yum update -y
    yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm || true
    yum install amazon-linux-extras

    # Who owns this package? It needs updating to not install modules under python2.7
    PYTHON=$(which python2) amazon-linux-extras install -y ruby2.6 rust1 python3.8
    PYTHON=$(which python2) amazon-linux-extras enable epel
    PYTHON=$(which python2) amazon-linux-extras enable corretto8
    yum install -y openssh-clients
}

mono() {
    rpm --import https://download.mono-project.com/repo/xamarin.gpg
    curl https://download.mono-project.com/repo/centos7-stable.repo | tee /etc/yum.repos.d/mono-centos7-stable.repo
}

symlink_all_the_things() {
    # Package owners should be doing this.
    # Note the version number at the end allows for upgrades to supersede these.
    update-alternatives --install /usr/bin/pip pip3 /usr/bin/pip3 300
    update-alternatives --install /usr/bin/ninja ninja /usr/bin/ninja-build 170
    update-alternatives --install /usr/bin/cmake cmake /usr/bin/cmake3 313
    update-alternatives --install /usr/bin/gcc-7 gcc /usr/bin/gcc 700
    update-alternatives --install /usr/bin/g++-7 g++ /usr/bin/g++ 700
    update-alternatives --install /usr/bin/g++-7 g++ /usr/bin/g++ 700
}

versions(){
    gcc --version
    cmake --version
    python3 --version
}

if [[ ${DISTRO} != "amazon linux" ]]; then
    echo "Target Amazon Linux, but running on $DISTRO: Nothing to do."
    exit 0;
else
    if [[ ${VERSION_ID} == '2' ]]; then
        al2_main;
    elif [[ ${VERSION_ID} == '2023' ]]; then
        al2023_main;
    fi
fi
