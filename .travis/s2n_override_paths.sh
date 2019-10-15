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

# Add all of our test dependencies to the PATH. Use Openssl 1.1.1 so the latest openssl is used for s_client
# integration tests.
export PATH=$PYTHON_INSTALL_DIR/bin:$OPENSSL_1_1_1_INSTALL_DIR/bin:$GNUTLS_INSTALL_DIR/bin:$SAW_INSTALL_DIR/bin:$Z3_INSTALL_DIR/bin:$SCAN_BUILD_INSTALL_DIR/bin:$PRLIMIT_INSTALL_DIR/bin:$LATEST_CLANG_INSTALL_DIR/bin:`pwd`/.travis/:~/.local/bin:$PATH
export LD_LIBRARY_PATH=$OPENSSL_1_1_1_INSTALL_DIR/lib:$LD_LIBRARY_PATH; 
export DYLD_LIBRARY_PATH=$OPENSSL_1_1_1_INSTALL_DIR/lib:$LD_LIBRARY_PATH;