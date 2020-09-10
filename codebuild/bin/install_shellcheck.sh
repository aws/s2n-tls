#!/bin/bash
#
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
source codebuild/bin/s2n_setup_env.sh

usage() {
    echo "install_shellcheck.sh"
    exit 1
}

install_aarch64_shellcheck() {
   wget https://github.com/koalaman/shellcheck/releases/download/v0.7.1/shellcheck-v0.7.1.linux.aarch64.tar.xz -O /tmp/shellcheck.tar.xz
   tar -Jxf /tmp/shellcheck.tar.xz -C /tmp 
   mv /tmp/shellcheck-v*/shellcheck /usr/local/bin/
   chmod 755 /usr/local/bin/shellcheck

}

if [ "$#" -ne "0" ]; then
    usage
fi

if [[ "$(uname -s)" == "Linux" ]]; then
	echo "Looks like we're on Linux"
	if [[ $(uname -m) == "x86_64" ]]; then
		uname -a
		echo "Looks like x86_64" 
    		which shellcheck || (sudo apt-get -qq update && sudo apt-get -qq install shellcheck -y)
	elif [[ $(uname -m) == "aarch64" ]]; then
		echo "Looks like aarch64"
		which shellcheck || install_aarch64_shellcheck
	fi
elif [ "$OS_NAME" == "darwin" ]; then
    # Installing an existing package is a "failure" in brew
    brew install shellcheck || true ;
else
    echo "Invalid platform! $OS_NAME"
    usage
fi
