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

usage() {
    echo "install_ctverif.sh install_dir"
    exit 1
}

if [ "$#" -ne "1" ]; then
    usage
fi

INSTALL_DIR=$1

cd "$INSTALL_DIR"

#install smack
git clone https://github.com/smackers/smack.git -b develop
cd smack/bin
git checkout 45e1fc5
./build.sh

# Disabling ShellCheck using https://github.com/koalaman/shellcheck/wiki/Directive
# Turn of Warning in one line as https://github.com/koalaman/shellcheck/wiki/SC1090
# shellcheck disable=SC1090
source "$INSTALL_DIR"/smack.environment

#install ctverif
cd "$INSTALL_DIR"
git clone --depth 1 https://github.com/imdea-software/verifying-constant-time.git -b test-automation

