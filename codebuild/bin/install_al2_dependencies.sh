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

if [[ ${DISTRO} != "amazon linux" ]]; then
    echo "Target AL2, but running on $DISTRO: Nothing to do."
    exit 0
fi

base_packages() {
    yum update -y
    yum erase -y openssl-devel || true
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


base_packages
mono
yum groupinstall -y "Development tools"
yum install -y clang cmake3 iproute net-tools nettle-devel nettle openssl11-static openssl11-libs openssl11-devel which sudo psmisc python3-pip  tcpdump unzip zlib-devel libtool ninja-build valgrind  wget which
symlink_all_the_things
