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
    echo "run_ctverif.sh install_dir"
    exit 1
}

if [ "$#" -ne "1" ]; then
    usage
fi

INSTALL_DIR=$1
export CTVERIF_DIR="${1}/verifying-constant-time"
SMACK_DIR="${1}/smack"

#Put the dependencies are on the path

# Disabling ShellCheck using https://github.com/koalaman/shellcheck/wiki/Directive
# Turn of Warning in one line as https://github.com/koalaman/shellcheck/wiki/SC1090
# shellcheck disable=SC1090
source "${INSTALL_DIR}/smack.environment"
export PATH="${SMACK_DIR}/bin:${SMACK_DIR}/build:${PATH}"
#Test that they are really there
which smack || echo "can't find smack"
which boogie || echo "can't find z3"
which llvm2bpl || echo "can't find llvm2bpl"

#copy the current version of the file to the test
cd "${BASE_S2N_DIR}/tests/ctverif"
cp "${BASE_S2N_DIR}/utils/s2n_safety.c" .
make clean

#run the test.  We expect both to pass, and none to fail
FAILED=0
EXPECTED_PASS=2
EXPECTED_FAIL=0
make 2>&1 | ./count_success.pl $EXPECTED_PASS $EXPECTED_FAIL || FAILED=1

if [ $FAILED == 1 ];
then
	printf "\\033[31;1mFAILED ctverif\\033[0m\\n"
	exit -1
else
	printf "\\033[32;1mPASSED ctverif\\033[0m\\n"
fi
