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

#Figlet is required for ctverif printing
sudo apt-get install -y figlet

#Install boogieman
gem install bam-bam-boogieman
which bam

#Install the apt-get dependencies from the smack build script: this way they will still be there
#when we get things from cache
DEPENDENCIES="git cmake python-yaml python-psutil unzip wget python3-yaml"
DEPENDENCIES+=" mono-complete libz-dev libedit-dev"
DEPENDENCIES+=" clang-3.9 llvm-3.9 llvm-3.9-dev"

# Adding MONO repository
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
echo "deb http://download.mono-project.com/repo/ubuntu trusty main" | sudo tee /etc/apt/sources.list.d/mono-official.list

sudo apt-get update -o Acquire::CompressionTypes::Order::=gz
sudo apt-get install -y ${DEPENDENCIES}
pip install pyyaml

LLVM_SHORT_VERSION=3.9

sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${LLVM_SHORT_VERSION} 30
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${LLVM_SHORT_VERSION} 30
sudo update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-${LLVM_SHORT_VERSION} 30
sudo update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-${LLVM_SHORT_VERSION} 30
sudo update-alternatives --install /usr/bin/llvm-dis llvm-dis /usr/bin/llvm-dis-${LLVM_SHORT_VERSION} 30

which clang
clang --version
clang-3.9 --version

mkdir -p ~/override_clang
ln -s /usr/bin/clang          ~/override_clang/clang
ln -s /usr/bin/clang++        ~/override_clang/clang++
ln -s /usr/bin/llvm-config   ~/override_clang/llvm-config
ln -s /usr/bin/llvm-link      ~/override_clang/llvm-link
ln -s /usr/bin/llvm-dis       ~/override_clang/llvm-dis
sudo chmod +x ~/override_clang/*

export PATH="$HOME/override_clang/:${PATH}"
which clang
clang --version
clang-3.9 --version

which python
python --version
pip install psutil
