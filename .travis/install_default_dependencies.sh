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

 # Install latest version of clang, clang++, and llvm-symbolizer. Needed for fuzzing.
if [[ "$TESTS" == "fuzz" || "$TESTS" == "ALL" || "$LATEST_CLAG" == "true" ]] && [[ ! -d "$LATEST_CLANG_INSTALL_DIR" ]]; then
    mkdir -p "$LATEST_CLANG_INSTALL_DIR";
    .travis/install_clang.sh "$(mktemp -d)" "$LATEST_CLANG_INSTALL_DIR" "$TRAVIS_OS_NAME" > /dev/null ;
fi

# Download and Install LibFuzzer with latest clang
if [[ "$TESTS" == "fuzz" || "$TESTS" == "ALL" ]] && [[ ! -d "$LIBFUZZER_INSTALL_DIR" ]]; then
    mkdir -p "$LIBFUZZER_INSTALL_DIR";
    PATH=$LATEST_CLANG_INSTALL_DIR/bin:$PATH .travis/install_libFuzzer.sh "$(mktemp -d)" "$LIBFUZZER_INSTALL_DIR" "$TRAVIS_OS_NAME" > /dev/null ;
fi

# Download and Install Openssl 1.1.1
if [[ ("$S2N_LIBCRYPTO" == "openssl-1.1.1") || ("$TESTS" == "integration"  || "$TESTS" == "ALL" ) ]] && [[ ! -d "$OPENSSL_1_1_1_INSTALL_DIR" ]]; then
    mkdir -p "$OPENSSL_1_1_1_INSTALL_DIR";
    .travis/install_openssl_1_1_1.sh "$(mktemp -d)" "$OPENSSL_1_1_1_INSTALL_DIR" "$TRAVIS_OS_NAME" > /dev/null ;
fi

# Download and Install Openssl 1.0.2
if [[ "$S2N_LIBCRYPTO" == "openssl-1.0.2" ]] && [[ ! -d "$OPENSSL_1_0_2_INSTALL_DIR" ]]; then
    mkdir -p "$OPENSSL_1_0_2_INSTALL_DIR";
    .travis/install_openssl_1_0_2.sh "$(mktemp -d)" "$OPENSSL_1_0_2_INSTALL_DIR" "$TRAVIS_OS_NAME" > /dev/null ;
fi

# Download and Install the Openssl FIPS module and Openssl 1.0.2-fips
if [[ "$S2N_LIBCRYPTO" == "openssl-1.0.2-fips" ]] && [[ ! -d "$OPENSSL_1_0_2_FIPS_INSTALL_DIR" ]]; then
    .travis/install_openssl_1_0_2_fips.sh "$(mktemp -d)" "$OPENSSL_1_0_2_FIPS_INSTALL_DIR" "$TRAVIS_OS_NAME" ; fi

# Download and Install CppCheck
if [[ "$BUILD_S2N" == "true" ]] && [[ ! -d "$CPPCHECK_INSTALL_DIR" ]]; then
    mkdir -p "$CPPCHECK_INSTALL_DIR";
    .travis/install_cppcheck.sh "$CPPCHECK_INSTALL_DIR" > /dev/null ;
fi

# Download and Install LibreSSL
if [[ "$S2N_LIBCRYPTO" == "libressl" ]] && [[ ! -d "$LIBRESSL_INSTALL_DIR" ]]; then
    mkdir -p "$LIBRESSL_INSTALL_DIR";
    .travis/install_libressl.sh "$(mktemp -d)" "$LIBRESSL_INSTALL_DIR" > /dev/null ;
fi

# Install python linked with the latest Openssl for integration tests
if [[ "$TESTS" == "integration" || "$TESTS" == "ALL" ]] && [[ ! -d "$PYTHON_INSTALL_DIR" ]]; then
    mkdir -p "$PYTHON_INSTALL_DIR";
    .travis/install_python.sh "$OPENSSL_1_1_1_INSTALL_DIR" "$(mktemp -d)" "$PYTHON_INSTALL_DIR" > /dev/null ;
fi

# Download and Install GnuTLS for integration tests
if [[ "$TESTS" == "integration" || "$TESTS" == "ALL" ]] && [[ ! -d "$GNUTLS_INSTALL_DIR" ]]; then
    mkdir -p "$GNUTLS_INSTALL_DIR";
    .travis/install_gnutls.sh "$(mktemp -d)" "$GNUTLS_INSTALL_DIR" "$TRAVIS_OS_NAME" > /dev/null ;
fi

# Install SAW, Z3, and Yices for formal verification
if [[ "$SAW" == "true" || "$TESTS" == "ALL" ]] && [[ ! -d "$SAW_INSTALL_DIR" ]]; then
    mkdir -p "$SAW_INSTALL_DIR";
    .travis/install_saw.sh "$(mktemp -d)" "$SAW_INSTALL_DIR" > /dev/null ;
fi

if [[ "$SAW" == "true" || "$TESTS" == "ALL" ]] && [[ ! -d "$Z3_INSTALL_DIR" ]]; then
    mkdir -p "$Z3_INSTALL_DIR" && .travis/install_z3_yices.sh "$(mktemp -d)" "$Z3_INSTALL_DIR" > /dev/null ;
fi

# Install SSLyze for all Integration Tests
if [[ "$TESTS" == "integration" || "$TESTS" == "ALL" ]] ; then
    .travis/install_sslyze.sh
fi
