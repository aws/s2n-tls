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
source codebuild/bin/s2n_setup_env.sh


 # Install latest version of clang, clang++, and llvm-symbolizer. Needed for fuzzing.
if [[ "$TESTS" == "fuzz" || "$TESTS" == "ALL" || "$LATEST_CLANG" == "true" ]]; then
    mkdir -p "$LATEST_CLANG_INSTALL_DIR"||true
    codebuild/bin/install_clang.sh "$(mktemp -d)" "$LATEST_CLANG_INSTALL_DIR" "$OS_NAME" > /dev/null ;
fi

# Download and Install LibFuzzer with latest clang
if [[ "$TESTS" == "fuzz" || "$TESTS" == "ALL" ]]; then
    mkdir -p "$LIBFUZZER_INSTALL_DIR" || true
    PATH=$LATEST_CLANG_INSTALL_DIR/bin:$PATH codebuild/bin/install_libFuzzer.sh "$(mktemp -d)" "$LIBFUZZER_INSTALL_DIR" "$OS_NAME" > /dev/null ;
fi

# Download and Install Openssl 1.1.1
if [[ ("$S2N_LIBCRYPTO" == "openssl-1.1.1") || ("$TESTS" == "integration"  || "$TESTS" == "ALL" ) ]]; then
    mkdir -p "$OPENSSL_1_1_1_INSTALL_DIR"||true
    codebuild/bin/install_openssl_1_1_1.sh "$(mktemp -d)" "$OPENSSL_1_1_1_INSTALL_DIR" "$OS_NAME" > /dev/null ;
fi

# Download and Install Openssl 1.0.2
if [[ "$S2N_LIBCRYPTO" == "openssl-1.0.2" ]]; then
    mkdir -p "$OPENSSL_1_0_2_INSTALL_DIR"||true
    codebuild/bin/install_openssl_1_0_2.sh "$(mktemp -d)" "$OPENSSL_1_0_2_INSTALL_DIR" "$OS_NAME" > /dev/null ;
fi

# Download and Install the Openssl FIPS module and Openssl 1.0.2-fips
if [[ "$S2N_LIBCRYPTO" == "openssl-1.0.2-fips" ]] && [[ ! -d "$OPENSSL_1_0_2_FIPS_INSTALL_DIR" ]]; then
    codebuild/bin/install_openssl_1_0_2_fips.sh "$(mktemp -d)" "$OPENSSL_1_0_2_FIPS_INSTALL_DIR" "$OS_NAME" ; fi

# Download and Install CppCheck
if [[ "$BUILD_S2N" == "true" ]]; then
    mkdir -p "$CPPCHECK_INSTALL_DIR"||true
    codebuild/bin/install_cppcheck.sh "$CPPCHECK_INSTALL_DIR" > /dev/null ;
fi

# Download and Install LibreSSL
if [[ "$S2N_LIBCRYPTO" == "libressl" ]]; then
    mkdir -p "$LIBRESSL_INSTALL_DIR"||true
    codebuild/bin/install_libressl.sh "$(mktemp -d)" "$LIBRESSL_INSTALL_DIR" > /dev/null ;
fi

# Download and Install BoringSSL
if [[ "$S2N_LIBCRYPTO" == "boringssl" ]]; then
    codebuild/bin/install_boringssl.sh "$(mktemp -d)" "$BORINGSSL_INSTALL_DIR" > /dev/null ;
fi

# Install python linked with the latest Openssl for integration tests
if [[ "$TESTS" == "integration" || "$TESTS" == "ALL" ]]; then
    mkdir -p "$PYTHON_INSTALL_DIR"||true
    codebuild/bin/install_python.sh "$OPENSSL_1_1_1_INSTALL_DIR" "$(mktemp -d)" "$PYTHON_INSTALL_DIR" > /dev/null ;
fi

# Download and Install Openssl 0.9.8
if [[ "$TESTS" == "integration" || "$TESTS" == "ALL" ]]; then
    mkdir -p "$OPENSSL_0_9_8_INSTALL_DIR"||true
    codebuild/bin/install_openssl_0_9_8.sh "$(mktemp -d)" "$OPENSSL_0_9_8_INSTALL_DIR" "$OS_NAME" > /dev/null ;
fi

# Download and Install GnuTLS for integration tests
if [[ "$TESTS" == "integration" || "$TESTS" == "ALL" ]]; then
    mkdir -p "$GNUTLS_INSTALL_DIR"||true
    codebuild/bin/install_gnutls.sh "$(mktemp -d)" "$GNUTLS_INSTALL_DIR" "$OS_NAME" > /dev/null ;
fi

# Install SAW, Z3, and Yices for formal verification
if [[ "$SAW" == "true" || "$TESTS" == "ALL" ]]; then
    mkdir -p "$SAW_INSTALL_DIR"||true
    codebuild/bin/install_saw.sh "$(mktemp -d)" "$SAW_INSTALL_DIR" > /dev/null ;
fi

if [[ "$SAW" == "true" || "$TESTS" == "ALL" ]]; then
    mkdir -p "$Z3_INSTALL_DIR"||true
    codebuild/bin/install_z3_yices.sh "$(mktemp -d)" "$Z3_INSTALL_DIR" > /dev/null ;
fi

# Install SSLyze for all Integration Tests
if [[ "$TESTS" == "integration" || "$TESTS" == "ALL" ]] ; then
    codebuild/bin/install_sslyze.sh
fi
