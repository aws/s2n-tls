#!/bin/bash

# Setup Default Build Config
: "${S2N_LIBCRYPTO:=openssl-1.1.0}"
: "${BUILD_S2N:=true}"
: "${GCC6_REQUIRED:=true}"
: "${LATEST_CLANG:=true}"
: "${TESTS:=integration}"

# Setup the Travis cache directory paths.
# Set Env Variables with defaults if they aren't already set
: "${BASE_S2N_DIR:=$(pwd)}"
: "${PYTHON_INSTALL_DIR:=$(pwd)/test-deps/python}"
: "${GNUTLS_INSTALL_DIR:=$(pwd)/test-deps/gnutls}"
: "${PRLIMIT_INSTALL_DIR:=$(pwd)/test-deps/prlimit}"
: "${SAW_INSTALL_DIR:=$(pwd)/test-deps/saw}"
: "${Z3_INSTALL_DIR:=$(pwd)/test-deps/z3}"
: "${LIBFUZZER_INSTALL_DIR:=$(pwd)/test-deps/libfuzzer}"
: "${LATEST_CLANG_INSTALL_DIR:=$(pwd)/test-deps/clang}"
: "${SCAN_BUILD_INSTALL_DIR:=$(pwd)/test-deps/scan-build}"
: "${OPENSSL_1_1_0_INSTALL_DIR:=$(pwd)/test-deps/openssl-1.1.0}"
: "${OPENSSL_1_0_2_INSTALL_DIR:=$(pwd)/test-deps/openssl-1.0.2}"
: "${LIBRESSL_INSTALL_DIR:=$(pwd)/test-deps/libressl}"
: "${CPPCHECK_INSTALL_DIR:=$(pwd)/test-deps/cppcheck}"
: "${CTVERIF_INSTALL_DIR:=$(pwd)/test-deps/ctverif}"
: "${FUZZ_TIMEOUT_SEC:=10}"

# Openssl 1.1.x-master is not added to Travis cache because we want to build against the latest
: "${OPENSSL_1_1_X_MASTER_INSTALL_DIR:=$(mktemp -d)}"

# Set TRAVIS_OS_NAME (if it isn't set) in case we're not running on Travis
unamestr=$(uname)
if [[ "$unamestr" == 'Linux' ]]; then
   : "${TRAVIS_OS_NAME:=linux}"
elif [[ "$unamestr" == 'Darwin' ]]; then
   : "${TRAVIS_OS_NAME:=osx}"
fi

# Export all Env Variables
export S2N_LIBCRYPTO
export BUILD_S2N
export GCC6_REQUIRED
export LATEST_CLANG
export TESTS
export BASE_S2N_DIR
export PYTHON_INSTALL_DIR
export GNUTLS_INSTALL_DIR
export PRLIMIT_INSTALL_DIR
export SAW_INSTALL_DIR
export Z3_INSTALL_DIR
export LIBFUZZER_INSTALL_DIR
export LATEST_CLANG_INSTALL_DIR
export SCAN_BUILD_INSTALL_DIR
export OPENSSL_1_1_0_INSTALL_DIR
export OPENSSL_1_0_2_INSTALL_DIR
export LIBRESSL_INSTALL_DIR
export CPPCHECK_INSTALL_DIR
export CTVERIF_INSTALL_DIR
export OPENSSL_1_1_X_MASTER_INSTALL_DIR
export FUZZ_TIMEOUT_SEC
export TRAVIS_OS_NAME

# Add all of our test dependencies to the PATH. Use Openssl 1.1.0 so the latest openssl is used for s_client
# integration tests.
export PATH=$PYTHON_INSTALL_DIR/bin:$OPENSSL_1_1_0_INSTALL_DIR/bin:$GNUTLS_INSTALL_DIR/bin:$SAW_INSTALL_DIR/bin:$Z3_INSTALL_DIR/bin:$SCAN_BUILD_INSTALL_DIR/bin:$LATEST_CLANG_INSTALL_DIR/bin:$PATH
export LD_LIBRARY_PATH=$OPENSSL_1_1_0_INSTALL_DIR/lib:$LD_LIBRARY_PATH; export DYLD_LIBRARY_PATH=$OPENSSL_1_1_0_INSTALL_DIR/lib:$LD_LIBRARY_PATH;

# Select the libcrypto to build s2n against. If this is unset, default to the latest stable version(Openssl 1.1.0)
if [[ -z $S2N_LIBCRYPTO ]]; then export LIBCRYPTO_ROOT=$OPENSSL_1_1_0_INSTALL_DIR ; fi
if [[ "$S2N_LIBCRYPTO" == "openssl-1.1.0" ]]; then export LIBCRYPTO_ROOT=$OPENSSL_1_1_0_INSTALL_DIR ; fi
if [[ "$S2N_LIBCRYPTO" == "openssl-1.1.x-master" ]]; then export LIBCRYPTO_ROOT=$OPENSSL_1_1_X_MASTER_INSTALL_DIR ; fi
if [[ "$S2N_LIBCRYPTO" == "openssl-1.0.2" ]]; then export LIBCRYPTO_ROOT=$OPENSSL_1_0_2_INSTALL_DIR ; fi
if [[ "$S2N_LIBCRYPTO" == "openssl-1.0.2-fips" ]]; then export LIBCRYPTO_ROOT=$OPENSSL_1_0_2_FIPS_INSTALL_DIR ; export S2N_TEST_IN_FIPS_MODE=1 ; fi
if [[ "$S2N_LIBCRYPTO" == "libressl" ]]; then export LIBCRYPTO_ROOT=$LIBRESSL_INSTALL_DIR ; fi

# Create a link to the selected libcrypto. This shouldn't be needed when LIBCRYPTO_ROOT is set, but some tests
# have the "libcrypto-root" directory path hardcoded.
rm -rf libcrypto-root && ln -s "$LIBCRYPTO_ROOT" libcrypto-root

# Set the libfuzzer to use for fuzz tests
export LIBFUZZER_ROOT=$LIBFUZZER_INSTALL_DIR
