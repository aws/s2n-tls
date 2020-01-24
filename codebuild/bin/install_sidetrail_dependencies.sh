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

set -e
set -x

#Install boogieman
gem install bam-bam-boogieman
which bam

#Install the apt-get dependencies from the smack build script: this way they will still be there
#when we get things from cache

# For python- either use pip or apt, don't do both.
DEPENDENCIES="git cmake python-yaml python-psutil unzip wget python-pip"
DEPENDENCIES+=" mono-complete libz-dev libedit-dev"
# Smack needs a clang that can do -Xclang -disable-O0-optnone
DEPENDENCIES+=" figlet clang-8.0 llvm-8.0 llvm-8.0-dev"


# Adding MONO repository
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
echo "deb http://download.mono-project.com/repo/ubuntu trusty main" | sudo tee /etc/apt/sources.list.d/mono-official.list

apt-get update -o Acquire::CompressionTypes::Order::=gz
apt-get install -y ${DEPENDENCIES}

LLVM_SHORT_VERSION=8.0

# TODO: This should be done at a higher level.
update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${LLVM_SHORT_VERSION} 1000
update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${LLVM_SHORT_VERSION} 1000
update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-${LLVM_SHORT_VERSION} 1000
update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-${LLVM_SHORT_VERSION} 1000
update-alternatives --install /usr/bin/llvm-dis llvm-dis /usr/bin/llvm-dis-${LLVM_SHORT_VERSION} 1000

#TODO: Why do two layers of symlink?
mkdir -p ~/override_clang
ln -s /usr/bin/clang          ~/override_clang/clang
ln -s /usr/bin/clang++        ~/override_clang/clang++
ln -s /usr/bin/llvm-config   ~/override_clang/llvm-config
ln -s /usr/bin/llvm-link      ~/override_clang/llvm-link
ln -s /usr/bin/llvm-dis       ~/override_clang/llvm-dis
chmod +x ~/override_clang/*

export PATH="$HOME/override_clang/:${PATH}"

which python
python --version
