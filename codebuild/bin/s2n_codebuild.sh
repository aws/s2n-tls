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

source codebuild/bin/s2n_setup_env.sh

# Use prlimit to set the memlock limit to unlimited for linux. OSX is unlimited by default
# Codebuild Containers aren't allowing prlimit changes (and aren't being caught with the usual cgroup check)
if [[ "$OS_NAME" == "linux" && -n "$CODEBUILD_BUILD_ARN" ]]; then
    PRLIMIT_LOCATION=`which prlimit`
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

if [[ "$OS_NAME" == "linux" && "$TESTS" == "valgrind" ]]; then
    # For linux make a build with debug symbols and run valgrind
    # We have to output something every 9 minutes, as some test may run longer than 10 minutes
    # and will not produce any output
    while sleep 9m; do echo "=====[ $SECONDS seconds still running ]====="; done &
    S2N_DEBUG=true make -j $JOBS valgrind
    kill %1
fi

if [[ "$OS_NAME" == "linux" && ( ("$TESTS" == "integration") || ("$TESTS" == "integrationv2") ) ]]; then
    make -j $JOBS
fi

# Build and run unit tests with scan-build for osx. scan-build bundle isn't available for linux
if [[ "$OS_NAME" == "osx" && "$TESTS" == "integration" ]]; then
    scan-build --status-bugs -o /tmp/scan-build make -j$JOBS; STATUS=$?; test $STATUS -ne 0 && cat /tmp/scan-build/*/* ; [ "$STATUS" -eq "0" ];
fi

CMAKE_PQ_OPTION="S2N_NO_PQ=False"
if [[ -n "$S2N_NO_PQ" ]]; then
    CMAKE_PQ_OPTION="S2N_NO_PQ=True"
fi

# Run Multiple tests on one flag.
if [[ "$TESTS" == "ALL" || "$TESTS" == "sawHMACPlus" ]] && [[ "$OS_NAME" == "linux" ]]; then make -C tests/saw tmp/verify_HMAC.log tmp/verify_drbg.log sike failure-tests; fi

# Run Individual tests
if [[ "$TESTS" == "ALL" || "$TESTS" == "unit" ]]; then cmake . -Bbuild -DCMAKE_PREFIX_PATH=$LIBCRYPTO_ROOT -D${CMAKE_PQ_OPTION}; cmake --build ./build; make -C build test ARGS=-j$(nproc); fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "interning" ]]; then ./codebuild/bin/test_libcrypto_interning.sh; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "asan" ]]; then make clean; S2N_ADDRESS_SANITIZER=1 make -j $JOBS ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "integration" ]]; then make clean; S2N_NO_SSLYZE=1 make integration ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "integrationv2" ]]; then $CB_BIN_DIR/install_s2n_head.sh "$(mktemp -d)"; make clean; make integrationv2 ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "fuzz" ]]; then (make clean && make fuzz) ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "benchmark" ]]; then (make clean && make benchmark) ; fi
if [[ "$TESTS" == "sawHMAC" ]] && [[ "$OS_NAME" == "linux" ]]; then make -C tests/saw/ tmp/verify_HMAC.log ; fi
if [[ "$TESTS" == "sawDRBG" ]]; then make -C tests/saw tmp/verify_drbg.log ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "tls" ]]; then make -C tests/saw tmp/verify_handshake.log ; fi
if [[ "$TESTS" == "sawHMACFailure" ]]; then make -C tests/saw failure-tests ; fi
# Below runs sike r_1 r_2 and x86
if [[ "$TESTS" == "sawSIKE" ]]; then make -C tests/saw sike ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "sawBIKE" ]]; then make -C tests/saw bike ; fi

# Generate *.gcov files that can be picked up by the CodeCov.io Bash helper script. Don't run lcov or genhtml
# since those will delete .gcov files as they're processed.
if [[ "$CODECOV_IO_UPLOAD" == "true" && "$FUZZ_COVERAGE" != "true" ]]; then
    make run-gcov;
fi
