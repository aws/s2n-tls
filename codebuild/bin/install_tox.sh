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

set -e

usage() {
    echo "install_tox.sh install_dir"
    exit 1
}

if [ "$#" -ne "1" ]; then
    usage
fi

INSTALL_DIR=$1
cd "$INSTALL_DIR"

wget https://files.pythonhosted.org/packages/d6/f0/14e68ea6e4bf9ef280c476fc1ab68782032d7fb1178124b1326ad6dfd039/tox-3.24.5-py2.py3-none-any.whl
/usr/bin/python3 -m pip install tox-3.24.5-py2.py3-none-any.whl
