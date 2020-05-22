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
if [[ ("$S2N_LIBCRYPTO" == "openssl-1.1.1") || ("$TESTS" == "integration" || "$TESTS" == "integrationv2" || "$TESTS" == "ALL" ) ]]; then
    if [[ ! -x "$OPENSSL_1_1_1_INSTALL_DIR/bin/openssl" ]]; then
      mkdir -p "$OPENSSL_1_1_1_INSTALL_DIR"||true
      codebuild/bin/install_openssl_1_1_1.sh "$(mktemp -d)" "$OPENSSL_1_1_1_INSTALL_DIR" "$OS_NAME" > /dev/null ;
    fi
fi

# Download and Install Openssl 1.0.2
if [[ "$S2N_LIBCRYPTO" == "openssl-1.0.2" && ! -d "$OPENSSL_1_0_2_INSTALL_DIR" ]]; then
    mkdir -p "$OPENSSL_1_0_2_INSTALL_DIR"||true
    codebuild/bin/install_openssl_1_0_2.sh "$(mktemp -d)" "$OPENSSL_1_0_2_INSTALL_DIR" "$OS_NAME" > /dev/null ;
fi

# Download and Install the Openssl FIPS module and Openssl 1.0.2-fips
if [[ "$S2N_LIBCRYPTO" == "openssl-1.0.2-fips" ]] && [[ ! -d "$OPENSSL_1_0_2_FIPS_INSTALL_DIR" ]]; then
    codebuild/bin/install_openssl_1_0_2_fips.sh "$(mktemp -d)" "$OPENSSL_1_0_2_FIPS_INSTALL_DIR" "$OS_NAME" ; fi

# Download and Install LibreSSL
if [[ "$S2N_LIBCRYPTO" == "libressl" && ! -d "$LIBRESSL_INSTALL_DIR" ]]; then
    mkdir -p "$LIBRESSL_INSTALL_DIR"||true
    codebuild/bin/install_libressl.sh "$(mktemp -d)" "$LIBRESSL_INSTALL_DIR" > /dev/null ;
fi

# Download and Install BoringSSL
if [[ "$S2N_LIBCRYPTO" == "boringssl" && ! -d "$BORINGSSL_INSTALL_DIR" ]]; then
    codebuild/bin/install_boringssl.sh "$(mktemp -d)" "$BORINGSSL_INSTALL_DIR" > /dev/null ;
fi

if [[ "$TESTS" == "integration" || "$TESTS" == "integrationv2" || "$TESTS" == "ALL" ]]; then
    # Install tox if running on Ubuntu(only supported Linux at this time)
    if [[ "$OS_NAME" == "linux" && ! -x `which tox` ]]; then
        apt-get -y install tox
    fi

    if [[ ! -x "$OPENSSL_0_9_8_INSTALL_DIR/bin/openssl" ]]; then
      # Download and Install Openssl 0.9.8
      mkdir -p "$OPENSSL_0_9_8_INSTALL_DIR"||true
      codebuild/bin/install_openssl_0_9_8.sh "$(mktemp -d)" "$OPENSSL_0_9_8_INSTALL_DIR" "$OS_NAME" > /dev/null ;
    fi

    if [[ ! -x "$GNUTLS_INSTALL_DIR/bin/gnutls-cli" ]]; then
      # Download and Install GnuTLS for integration tests
      mkdir -p "$GNUTLS_INSTALL_DIR"||true
      codebuild/bin/install_gnutls.sh "$(mktemp -d)" "$GNUTLS_INSTALL_DIR" "$OS_NAME" > /dev/null ;
    fi

    # Install SSLyze for all Integration Tests
    codebuild/bin/install_sslyze.sh
fi

# Install SAW, Z3, and Yices for formal verification
if [[ "$SAW" == "true" || "$TESTS" == "ALL" ]]; then
    mkdir -p "$SAW_INSTALL_DIR"||true
    codebuild/bin/install_saw.sh "$(mktemp -d)" "$SAW_INSTALL_DIR" > /dev/null ;

    mkdir -p "$Z3_INSTALL_DIR"||true
    codebuild/bin/install_z3_yices.sh "$(mktemp -d)" "$Z3_INSTALL_DIR" > /dev/null ;
fi
