#!/bin/bash
# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#!/bin/bash

set -e

if [ "$#" -ne 3 ]; then
	echo "install_python.sh libcrypto_root build_dir install_dir"
	exit 1
fi

LIBCRYPTO_ROOT=$1
BUILD_DIR=$2
INSTALL_DIR=$3

cd "$BUILD_DIR"
# Originally from: https://www.python.org/ftp/python/3.6.0/Python-3.6.0.tgz
curl --retry 3 https://s3-us-west-2.amazonaws.com/s2n-public-test-dependencies/2017-08-29_Python-3.6.0.tgz --output Python-3.6.0.tgz
tar xzf Python-3.6.0.tgz
cd Python-3.6.0
 CPPFLAGS="-I$LIBCRYPTO_ROOT/include" LDFLAGS="-Wl,-rpath,$LIBCRYPTO_ROOT/lib -L$LIBCRYPTO_ROOT/lib" ./configure --prefix="$INSTALL_DIR"
make
make install
