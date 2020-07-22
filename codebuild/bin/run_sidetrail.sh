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

usage() {
    echo "run_sidetrail.sh install_dir s2n_dir"
    exit 1
}

runSingleTest() {
    cd "${BASE_S2N_DIR}/tests/sidetrail/working/${1}"
    ./copy_as_needed.sh
    make clean
    make 2>&1 | tee out.txt

    ../../count_success.pl 1 0 out.txt
}

runNegativeTest() {
    cd "${BASE_S2N_DIR}/tests/sidetrail/working/${1}"
    ./copy_as_needed.sh
    make clean
    make 2>&1 | tee out.txt

    ../../count_success.pl 0 1 out.txt
}

if [[ "$#" -ne "2" ]]; then
    usage
fi

INSTALL_DIR=$1
SMACK_DIR="${1}/smack"
BASE_S2N_DIR=$2

#Put the dependencies on the path

# Disabling ShellCheck using https://github.com/koalaman/shellcheck/wiki/Directive
# Turn of Warning in one line as https://github.com/koalaman/shellcheck/wiki/SC1090
# shellcheck disable=SC1090
source "${INSTALL_DIR}/smack.environment"
export PATH="${SMACK_DIR}/bin:${SMACK_DIR}/build:${PATH}"
#Test that they are really there
which smack || echo "can't find smack"
which boogie || echo "can't find z3"
which llvm2bpl || echo "can't find llvm2bpl"
which clang
clang --version
echo $BOOGIE
echo $CORRAL

runNegativeTest "s2n-record-read-cbc-negative-test"
runSingleTest "s2n-cbc" # Takes 6m 30s
runSingleTest "s2n-record-read-aead"
runSingleTest "s2n-record-read-cbc"
runSingleTest "s2n-record-read-composite"
runSingleTest "s2n-record-read-stream"

