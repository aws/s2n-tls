#!/bin/bash
# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

# Need to upgrade pyOpenSSL before pip on a fresh Ubuntu 16.04 install: https://stackoverflow.com/a/48569233
sudo python -m easy_install --upgrade pyOpenSSL

pip install --user --upgrade pip setuptools
pip install --user --upgrade nassl sslyze==1.4.0

which sslyze
sslyze --version