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

# Defer overriding LD_LIBRARY_PATH so that the overriden paths don't interfere with test install scripts.
# Some Test install scripts use curl commands to download files from S3, but those commands don't work when forced to load OpenSSL 1.1.1
source .travis/s2n_override_paths.sh

if [[ "$BUILD_S2N" == "true" ]]; then
    .travis/run_cppcheck.sh "$CPPCHECK_INSTALL_DIR";
    .travis/copyright_mistake_scanner.sh;
    .travis/grep_simple_mistakes.sh;
fi

if [[ "$BUILD_S2N" == "true" && "$TRAVIS_OS_NAME" == "linux" ]]; then
    .travis/run_kwstyle.sh;
    .travis/cpp_style_comment_linter.sh;
fi

# Use prlimit to set the memlock limit to unlimited for linux. OSX is unlimited by default
if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then
    PRLIMIT_LOCATION=`which prlimit`
    # sudo may not be able to find prlimit if we installed it in the test-deps directory. Force it to use the one on our current path.
    sudo -E ${PRLIMIT_LOCATION} --pid "$$" --memlock=unlimited:unlimited;
fi

# Set the version of GCC as Default if it's required
if [[ -n "$GCC_VERSION" ]] && [[ "$GCC_VERSION" != "NONE" ]]; then
    alias gcc=$(which gcc-$GCC_VERSION);
fi

# Find if the environment has more than 8 cores
JOBS=8
if [[ -x "$(command -v nproc)" ]]; then
    UNITS=$(nproc);
    if [[ $UNITS -gt $JOBS ]]; then
        JOBS=$UNITS;
    fi
fi

make clean;

echo "Using $JOBS jobs for make..";

if [[ "$TRAVIS_OS_NAME" == "linux" && "$TESTS" == "valgrind" ]]; then
    # For linux make a build with debug symbols and run valgrind
    # We have to output something every 9 minutes, as some test may run longer than 10 minutes
    # and will not produce any output
    while sleep 9m; do echo "=====[ $SECONDS seconds still running ]====="; done &
    S2N_DEBUG=true make -j $JOBS valgrind
    kill %1
fi

if [[ "$TRAVIS_OS_NAME" == "linux" && (("$TESTS" == "integration") || ("$TESTS" == "unit")) ]]; then
    make -j $JOBS
fi

# Build and run unit tests with scan-build for osx. scan-build bundle isn't available for linux
if [[ "$TRAVIS_OS_NAME" == "osx" && "$TESTS" == "integration" ]]; then  
    scan-build --status-bugs -o /tmp/scan-build make -j$JOBS; STATUS=$?; test $STATUS -ne 0 && cat /tmp/scan-build/*/* ; [ "$STATUS" -eq "0" ];
fi

if [[ "$TESTS" == "ALL" || "$TESTS" == "asan" ]]; then make clean; S2N_ADDRESS_SANITIZER=1 make -j $JOBS ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "integration" ]]; then make clean; make integration ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "fuzz" ]]; then (make clean && make fuzz) ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "sawHMAC" ]] && [[ "$TRAVIS_OS_NAME" == "linux" ]]; then make -C tests/saw/ tmp/"verify_s2n_hmac_$SAW_HMAC_TEST".log ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "sawDRBG" ]]; then make -C tests/saw tmp/verify_drbg.log ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "tls" ]]; then
    # We have to output something every 9 minutes, as some proofs may run longer than 10 minutes
    while sleep 9m; do echo "=====[ $SECONDS seconds still running ]====="; done &
    make -C tests/saw tmp/verify_handshake.log
    kill %1
fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "sawHMACFailure" ]]; then make -C tests/saw failure-tests ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "ctverif" ]]; then .travis/run_ctverif.sh "$CTVERIF_INSTALL_DIR" ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "sawSIKE_r1" ]]; then make -C tests/saw sike_r1 ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "sawBIKE_r1" ]]; then make -C tests/saw bike_r1 ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "sidetrail" ]]; then .travis/run_sidetrail.sh "$SIDETRAIL_INSTALL_DIR" "$PART" ; fi

# Generate *.gcov files that can be picked up by the CodeCov.io Bash helper script. Don't run lcov or genhtml 
# since those will delete .gcov files as they're processed.
if [[ -n "$CODECOV_IO_UPLOAD" ]]; then
    make run-gcov;
fi
