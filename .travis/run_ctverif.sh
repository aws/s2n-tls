#!/bin/bash
# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
    echo "run_ctverif.sh install_dir"
    exit 1
}

if [ "$#" -ne "1" ]; then
    usage
fi

INSTALL_DIR=$1
CTVERIF_DIR="${1}/verifying-constant-time"

source "${INSTALL_DIR}/smack.environment"

FAILED=0

cd "${CTVERIF_DIR}/examples/sort"
pwd
make clean
make || FAILED=1

if [ $FAILED == 1 ];
then
	printf "\033[31;1mFAILED ctverif\033[0m\n"
	exit -1
else
	printf "\033[32;1mPASSED ctverif\033[0m\n"
fi
