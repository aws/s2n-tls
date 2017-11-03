#!/bin/bash

set -ex

# Use prlimit to set the memlock limit to unlimited for linux. OSX is unlimited by default
if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then sudo -E "$PRLIMIT_INSTALL_DIR"/bin/prlimit --pid "$$" --memlock=unlimited:unlimited ; fi

if [[ "$BUILD_S2N" == "true" ]]; then .travis/run_cppcheck.sh "$CPPCHECK_INSTALL_DIR"; fi
if [[ "$BUILD_S2N" == "true" && "$TRAVIS_OS_NAME" == "linux" ]]; then .travis/run_kwstyle.sh ; fi

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

