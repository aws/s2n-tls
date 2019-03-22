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

#Figlet is required for ctverif printing
sudo apt-get install -y figlet

#Install boogieman
sudo gem install --pre bam-bam-boogieman

#Install the apt-get dependencies from the smack build script: this way they will still be there
#when we get things from cache
DEPENDENCIES="git cmake python-yaml python-psutil unzip wget python3-yaml"
DEPENDENCIES+=" clang-3.7 llvm-3.7 mono-complete libz-dev libedit-dev"

# Adding LLVM repository
sudo add-apt-repository "deb http://llvm-apt.ecranbleu.org/apt/trusty/ llvm-toolchain-trusty-3.7 main"
wget --no-verbose -O - http://llvm-apt.ecranbleu.org/apt/llvm-snapshot.gpg.key | sudo apt-key add -

# Adding MONO repository
sudo add-apt-repository "deb http://download.mono-project.com/repo/debian wheezy main"
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF

#    echo "deb http://download.mono-project.com/repo/debian wheezy main" | sudo tee /etc/apt/sources.list.d/mono-xamarin.list
sudo apt-get update -o Acquire::CompressionTypes::Order::=gz
sudo apt-get install -y ${DEPENDENCIES}
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-3.7 20
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-3.7 20
sudo update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-3.7 20
sudo update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-3.7 20
sudo update-alternatives --install /usr/bin/llvm-dis llvm-dis /usr/bin/llvm-dis-3.7 20
pip install pyyaml

which python
python --version
pip install psutil
