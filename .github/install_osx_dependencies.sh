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

function brew_install_if_not_installed () {
    brew list $1 &>/dev/null || brew install $1
}

brew update

brew_install_if_not_installed gnu-indent
brew_install_if_not_installed coreutils
brew_install_if_not_installed cppcheck
brew_install_if_not_installed pkg-config  # for gnutls compilation
brew_install_if_not_installed ninja
brew_install_if_not_installed openssl@1.1 # for libcrypto
