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
    local test_path=$1
    local test_name=$(basename "$test_path" .py)

    echo "Running test $test_name"

    export S2N_INTEG_TEST=1
    export TOX_TEST_NAME="$test_path"

    if [[ "$S2N_INTEG_NIX" == "1" ]]; then
        echo "[Nix] Running with pytest directly (env already set)"
        uv run pytest \
            -x -n=auto --reruns=2 -rpfs --durations=10 \
            --log-cli-level=DEBUG \
            --provider-version="${S2N_LIBCRYPTO}" \
            "$test_path"
    else
        echo "[CodeBuild] Running with full env setup"

        export LD_LIBRARY_PATH="${PROJECT_SOURCE_DIR}/libcrypto-root/lib:${PROJECT_SOURCE_DIR}/test-deps/openssl-1.1.1/lib:${PROJECT_SOURCE_DIR}/test-deps/gnutls37/nettle/lib:$LD_LIBRARY_PATH"
        export DYLD_LIBRARY_PATH="${PROJECT_SOURCE_DIR}/libcrypto-root/lib:$DYLD_LIBRARY_PATH"
        export PATH="${PROJECT_SOURCE_DIR}/bin:${PROJECT_SOURCE_DIR}/test-deps/openssl-1.1.1/bin:${PROJECT_SOURCE_DIR}/test-deps/gnutls37/bin:$PATH"
        export PYTHONNOUSERSITE=1

        uv run pytest \
            -x -n=auto --reruns=2 -rpfs --durations=10 \
            --log-cli-level=DEBUG \
            --provider-version="${S2N_LIBCRYPTO}" \
            "$test_path"
    fi
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
