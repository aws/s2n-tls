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


set -ex


if [[ "$BUILD_S2N" == "true" ]]; then
    .travis/run_cppcheck.sh "$CPPCHECK_INSTALL_DIR";
    .travis/copyright_mistake_scanner.sh;
fi


if [[ "$BUILD_S2N" == "true" && "$TRAVIS_OS_NAME" == "linux" ]]; then
    .travis/run_kwstyle.sh;
fi

# Use prlimit to set the memlock limit to unlimited for linux. OSX is unlimited by default
if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then
    sudo -E "$PRLIMIT_INSTALL_DIR"/bin/prlimit --pid "$$" --memlock=unlimited:unlimited;
fi

# Set GCC 6 as Default if it's required
if [[ "$GCC6_REQUIRED" == "true" ]]; then
    alias gcc=$(which gcc-6);
fi

if [[ "$TRAVIS_OS_NAME" == "linux" && "$TESTS" == "integration" ]]; then make -j 8   ; fi

# Build and run unit tests with scan-build for osx. scan-build bundle isn't available for linux
if [[ "$TRAVIS_OS_NAME" == "osx" && "$TESTS" == "integration" ]]; then  
    scan-build --status-bugs -o /tmp/scan-build make -j8; STATUS=$?; test $STATUS -ne 0 && cat /tmp/scan-build/*/* ; [ "$STATUS" -eq "0" ]; 
fi

if [[ "$TESTS" == "ALL" || "$TESTS" == "integration" ]]; then make clean; make integration ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "fuzz" ]]; then make clean && make fuzz ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "sawHMAC" ]] && [[ "$TRAVIS_OS_NAME" == "linux" ]]; then make -C tests/saw/ tmp/"verify_s2n_hmac_$SAW_HMAC_TEST".log ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "sawDRBG" ]]; then make -C tests/saw tmp/spec/DRBG/DRBG.log ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "tls" ]]; then make -C tests/saw tmp/handshake.log && make -C tests/saw tmp/cork-uncork.log ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "sawHMACFailure" ]]; then make -C tests/saw failure-tests ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "ctverif" ]]; then .travis/run_ctverif.sh "$CTVERIF_INSTALL_DIR" ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "sidewinder" ]]; then .travis/run_sidewinder.sh "$SIDEWINDER_INSTALL_DIR" ; fi

