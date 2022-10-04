#!/usr/bin/env bash
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

set -eu
source ./codebuild/bin/utils.sh

make install
source $HOME/.cargo/env
make -C bindings/rust
S2N_USE_CRITERION=1 TOX_TEST_NAME="$INTEGV2_TEST".py make integrationv2
S2N_USE_CRITERION=3 TOX_TEST_NAME="$INTEGV2_TEST".py make integrationv2
