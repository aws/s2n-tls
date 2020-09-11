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

set -ex

aarch64_install() {
	echo "old sslyze has a dep on nassl, which is not availabe for ARM.  Building it from source fails, skipping on"
	return
	yum install -y python3-devel
	pip install pathlib
	cd /tmp
	wget https://github.com/nabla-c0d3/nassl/archive/2.2.0.zip
	unzip 2.2.0.zip
	cd nassl-2.2.0
	python3 setup.py install --prefix /usr
}


if [[ "$(uname -m)" == "aarch64" ]]; then
	aarch64_install
}

python3 -m pip install --user --upgrade pip setuptools

# Version 3.0.0 introduces backwards incompatible changes in the JSON we parse.
# If we upgrade, the json format changes, breaking either Travis OR Codebuild.
python3 -m pip install --user "sslyze<3.0.0"

sudo ln -s /root/.local/bin/sslyze /usr/bin/sslyze || true

which sslyze
sslyze --version
