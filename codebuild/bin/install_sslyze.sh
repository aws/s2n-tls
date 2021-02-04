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
. codebuild/bin/s2n_setup_env.sh

aarch64_install() {
        echo "sslyze has a dependency on nassl, which will not build on ARM."
}

case "$ARCH" in
  "aarch64")
        aarch64_install
        exit 1
        ;;
  *)
        python3 -m pip install --user --upgrade pip setuptools
        # Version 3.0.0 introduces backwards incompatible changes in the JSON we parse.
        # TODO: unpin the sslyze version and update the json parsing sslyze output.
        python3 -m pip install --user "sslyze<3.0.0"
        sudo ln -s /root/.local/bin/sslyze /usr/bin/sslyze || true
        which sslyze
        sslyze --version
        ;;
esac
