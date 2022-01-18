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

set -e
source codebuild/bin/s2n_setup_env.sh

usage() {
    echo "install_shellcheck.sh"
    exit 1
}

install_shellcheck() {
   wget "https://github.com/koalaman/shellcheck/releases/download/v0.7.1/shellcheck-v0.7.1.linux.$ARCH.tar.xz" -O /tmp/shellcheck.tar.xz
   tar -Jxf /tmp/shellcheck.tar.xz -C /tmp
   mv /tmp/shellcheck-v*/shellcheck /usr/local/bin/
   chmod 755 /usr/local/bin/shellcheck
}

if [ "$#" -ne "0" ]; then
    usage
fi

case "$OS_NAME" in
  "amazon linux"|"linux")
    which shellcheck || install_shellcheck
    ;;
  "darwin" )
    brew install shellcheck || true ;
    ;;
  *)
    echo "Unknown platform"
    exit 255
    ;;
esac
