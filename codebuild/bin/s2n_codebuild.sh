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
echo "running with libcrypto: ${S2N_LIBCRYPTO}, gcc_version: ${GCC_VERSION}"

test_linked_libcrypto() {
    s2n_executable="$1"
    so_path="${LIBCRYPTO_ROOT}/lib/libcrypto.so"
    echo "Testing for linked libcrypto: ${so_path}"
    echo "ldd:"
    ldd "${s2n_executable}"
    ldd "${s2n_executable}" | grep "${so_path}" || \
        { echo "Linked libcrypto is incorrect."; exit 1; }
    echo "Test succeeded!"
}

setup_apache_server() {
    # Start the apache server if the list of tests isn't defined, meaning all tests
    # are to be run, or if the renegotiate test is included in the list of tests.
    if [[ -z $TOX_TEST_NAME ]] || [[ "${TOX_TEST_NAME}" == *"test_renegotiate_apache"* ]]; then
        source codebuild/bin/s2n_apache2.sh
        APACHE_CERT_DIR="$(pwd)/tests/pems"

        apache2_start "${APACHE_CERT_DIR}"
    fi
}

run_integration_v2_tests() {
    # checks if the Apache-related integration test is being run
    setup_apache_server
    # installs the current version of s2n (s2nc/s2nd) into a temporary directory
    "$CB_BIN_DIR/install_s2n_head.sh" "$(mktemp -d)"
    # generates a CMake-based build system inside the build/ directory
    cmake . -Bbuild \
            -DCMAKE_PREFIX_PATH=$LIBCRYPTO_ROOT \
            -DBUILD_SHARED_LIBS=on \
            -DPython3_EXECUTABLE=$(which python3)
    # "Now build everything"
    cmake --build ./build --clean-first -- -j $(nproc)

    # "doing a runtime check to verify which libcrypto library is actually linked to the s2nc and s2nd binaries"
    test_linked_libcrypto ./build/bin/s2nc
    test_linked_libcrypto ./build/bin/s2nd

    # Ensure the s2nc and s2nd binaries are available
    cp -f ./build/bin/s2nc "$BASE_S2N_DIR"/bin/s2nc
    cp -f ./build/bin/s2nd "$BASE_S2N_DIR"/bin/s2nd

    export PATH="$BASE_S2N_DIR/bin:$PATH"

    cd tests/integrationv2

    # Run tests — THIS replaces the old ctest loop
    uv run pytest . \
        --provider-version=${S2N_LIBCRYPTO} \
        -rpfs -n auto -x \
        --durations=10 --reruns=2 \
        -o log_cli=true --log-cli-level=DEBUG
}

run_unit_tests() {
    cmake . -Bbuild \
            -DCMAKE_PREFIX_PATH=$LIBCRYPTO_ROOT \
            -DBUILD_SHARED_LIBS=on
    cmake --build ./build -- -j $(nproc)
    test_linked_libcrypto ./build/bin/s2nc
    cmake --build build/ --target test -- ARGS="-L unit --output-on-failure -j $(nproc)"
}

# Run Multiple tests on one flag.
if [[ "$TESTS" == "ALL" || "$TESTS" == "sawHMACPlus" ]] && [[ "$OS_NAME" == "linux" ]]; then make -C tests/saw tmp/verify_HMAC.log tmp/verify_drbg.log failure-tests; fi

# Run Individual tests
if [[ "$TESTS" == "ALL" || "$TESTS" == "unit" ]]; then run_unit_tests; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "interning" ]]; then ./codebuild/bin/test_libcrypto_interning.sh; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "exec_leak" ]]; then ./codebuild/bin/test_exec_leak.sh; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "integrationv2" ]]; then run_integration_v2_tests; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "crt" ]]; then ./codebuild/bin/build_aws_crt_cpp.sh $(mktemp -d) $(mktemp -d); fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "sharedandstatic" ]]; then ./codebuild/bin/test_install_shared_and_static.sh $(mktemp -d); fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "dynamicload" ]]; then ./codebuild/bin/test_dynamic_load.sh $(mktemp -d); fi
if [[ "$TESTS" == "sawHMAC" ]] && [[ "$OS_NAME" == "linux" ]]; then make -C tests/saw/ tmp/verify_HMAC.log ; fi
if [[ "$TESTS" == "sawDRBG" ]]; then make -C tests/saw tmp/verify_drbg.log ; fi
if [[ "$TESTS" == "ALL" || "$TESTS" == "tls" ]]; then make -C tests/saw tmp/verify_handshake.log ; fi
if [[ "$TESTS" == "sawHMACFailure" ]]; then make -C tests/saw failure-tests ; fi