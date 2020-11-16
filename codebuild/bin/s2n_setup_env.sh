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

# TODO: Flag user if they didn't source this, values won't stick.

# Setup Default Build Config
: "${S2N_LIBCRYPTO:=openssl-1.1.1}"
: "${BUILD_S2N:=false}"
: "${GCC_VERSION:=NONE}"
: "${LATEST_CLANG:=false}"
: "${TESTS:=integration}"
: "${S2N_COVERAGE:=false}"
: "${LD_LIBRARY_PATH:=NONE}"

# Setup the cache directory paths.
# Set Env Variables with defaults if they aren't already set
: "${BASE_S2N_DIR:=$(pwd)}"
: "${TEST_DEPS_DIR:=$BASE_S2N_DIR/test-deps}"
: "${PYTHON_INSTALL_DIR:=$TEST_DEPS_DIR/python}"
: "${GNUTLS_INSTALL_DIR:=$TEST_DEPS_DIR/gnutls}"
: "${PRLIMIT_INSTALL_DIR:=$TEST_DEPS_DIR/prlimit}"
: "${SAW_INSTALL_DIR:=$TEST_DEPS_DIR/saw}"
: "${Z3_INSTALL_DIR:=$TEST_DEPS_DIR/z3}"
: "${LIBFUZZER_INSTALL_DIR:=$TEST_DEPS_DIR/libfuzzer}"
: "${LATEST_CLANG_INSTALL_DIR:=$TEST_DEPS_DIR/clang}"
: "${SCAN_BUILD_INSTALL_DIR:=$TEST_DEPS_DIR/scan-build}"
: "${OPENSSL_0_9_8_INSTALL_DIR:=$TEST_DEPS_DIR/openssl-0.9.8}"
: "${OPENSSL_1_1_1_INSTALL_DIR:=$TEST_DEPS_DIR/openssl-1.1.1}"
: "${OPENSSL_1_0_2_INSTALL_DIR:=$TEST_DEPS_DIR/openssl-1.0.2}"
: "${OQS_OPENSSL_1_1_1_INSTALL_DIR:=$TEST_DEPS_DIR/oqs_openssl-1.1.1}"
: "${OPENSSL_1_0_2_FIPS_INSTALL_DIR:=$TEST_DEPS_DIR/openssl-1.0.2-fips}"
: "${BORINGSSL_INSTALL_DIR:=$TEST_DEPS_DIR/boringssl}"
: "${AWSLC_INSTALL_DIR:=$TEST_DEPS_DIR/awslc}"
: "${LIBRESSL_INSTALL_DIR:=$TEST_DEPS_DIR/libressl-2.6.4}"
: "${CPPCHECK_INSTALL_DIR:=$TEST_DEPS_DIR/cppcheck}"
: "${CTVERIF_INSTALL_DIR:=$TEST_DEPS_DIR/ctverif}"
: "${SIDETRAIL_INSTALL_DIR:=$TEST_DEPS_DIR/sidetrail}"
: "${GB_INSTALL_DIR:=$TEST_DEPS_DIR/gb}"
: "${FUZZ_TIMEOUT_SEC:=10}"

# Set some environment vars for OS, Distro and architecture.
# Standardized as part of systemd http://0pointer.de/blog/projects/os-release
# Samples:
#  OS_NAME = "linux"
#  DISTRO="ubuntu"
#  VERSION_ID = "18.04"
#  VERSION_CODENAME = "bionic"
if [[ -f "/etc/os-release" ]]; then
  # AL2 doesn't provide a codename.
  . /etc/os-release
  export DISTRO=$(echo "$NAME"|tr "[:upper:]" "[:lower:]")
  export VERSION_ID=${VERSION_ID:-"unknown"}
  export VERSION_CODENAME=${VERSION_CODENAME:-"unknown"}
elif [[ -x "/usr/bin/sw_vers" ]]; then
  export DISTRO="apple"
  export VERSION_ID=$(sw_vers -productVersion|sed 's/:[[:space:]]*/=/g')
  export VERSION_CODENAME="unknown"  # not queriable via CLI
else
  export DISTRO="unknown"
  export VERSION_ID="unknown"
  export VERSION_CODENAME="unknown"
fi
export OS_NAME=$(uname -s|tr "[:upper:]" "[:lower:]")
export ARCH=$(uname -m)

# Export all Env Variables
export S2N_LIBCRYPTO
export BUILD_S2N
export GCC_VERSION
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
export OPENSSL_0_9_8_INSTALL_DIR
export OPENSSL_1_1_1_INSTALL_DIR
export OPENSSL_1_0_2_INSTALL_DIR
export OPENSSL_1_0_2_FIPS_INSTALL_DIR
export OQS_OPENSSL_1_1_1_INSTALL_DIR
export BORINGSSL_INSTALL_DIR
export AWSLC_INSTALL_DIR
export LIBRESSL_INSTALL_DIR
export CPPCHECK_INSTALL_DIR
export CTVERIF_INSTALL_DIR
export SIDETRAIL_INSTALL_DIR
export OPENSSL_1_1_X_MASTER_INSTALL_DIR
export FUZZ_TIMEOUT_SEC
export GB_INSTALL_DIR
export OS_NAME
export S2N_CORKED_IO

# S2N_COVERAGE should not be used with fuzz tests, use FUZZ_COVERAGE instead
if [[ "$S2N_COVERAGE" == "true" && "$TESTS" == "fuzz" ]]; then
    export S2N_COVERAGE="false"
    export FUZZ_COVERAGE="true"
fi

# Select the libcrypto to build s2n against. If this is unset, default to the latest stable version(Openssl 1.1.1)
if [[ -z $S2N_LIBCRYPTO ]]; then export LIBCRYPTO_ROOT=$OPENSSL_1_1_1_INSTALL_DIR ; fi
if [[ "$S2N_LIBCRYPTO" == "openssl-1.1.1" ]]; then export LIBCRYPTO_ROOT=$OPENSSL_1_1_1_INSTALL_DIR ; fi
if [[ "$S2N_LIBCRYPTO" == "openssl-1.0.2" ]]; then export LIBCRYPTO_ROOT=$OPENSSL_1_0_2_INSTALL_DIR ; fi
if [[ "$S2N_LIBCRYPTO" == "openssl-1.0.2-fips" ]]; then
    export LIBCRYPTO_ROOT=$OPENSSL_1_0_2_FIPS_INSTALL_DIR ;
    export S2N_TEST_IN_FIPS_MODE=1 ;
fi
if [[ "$S2N_LIBCRYPTO" == "boringssl" ]]; then export LIBCRYPTO_ROOT=$BORINGSSL_INSTALL_DIR ; fi

if [[ "$S2N_LIBCRYPTO" == "awslc" ]]; then export LIBCRYPTO_ROOT=$AWSLC_INSTALL_DIR ; fi

if [[ "$S2N_LIBCRYPTO" == "libressl" ]]; then export LIBCRYPTO_ROOT=$LIBRESSL_INSTALL_DIR ; fi

# Create a link to the selected libcrypto. This shouldn't be needed when LIBCRYPTO_ROOT is set, but some tests
# have the "libcrypto-root" directory path hardcoded.
rm -rf libcrypto-root && ln -s "$LIBCRYPTO_ROOT" libcrypto-root

# Set the libfuzzer to use for fuzz tests
export LIBFUZZER_ROOT=$LIBFUZZER_INSTALL_DIR

# Just recording in the output for debugging.
if [ -f "/etc/lsb-release" ]; then
  cat /etc/lsb-release
fi
echo "UID=$UID"
echo "OS_NAME=$OS_NAME"
echo "S2N_LIBCRYPTO=$S2N_LIBCRYPTO"
echo "LIBCRYPTO_ROOT=$LIBCRYPTO_ROOT"
echo "BUILD_S2N=$BUILD_S2N"
echo "GCC_VERSION=$GCC_VERSION"
echo "LATEST_CLANG=$LATEST_CLANG"
echo "TESTS=$TESTS"
echo "PATH=$PATH"
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"

