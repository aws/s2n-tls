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

set -e

OUT_DIR=$1

pushd $PWD

wget https://www.kernel.org/pub/linux/utils/util-linux/v2.25/util-linux-2.25.2.tar.gz
tar -xzvf util-linux-2.25.2.tar.gz
cd util-linux-2.25.2
./configure ADJTIME_PATH=/var/lib/hwclock/adjtime --disable-chfn-chsh --disable-login --disable-nologin --disable-su --disable-setpriv --disable-runuser --disable-pylibmount --disable-static --without-python --without-systemd --without-systemdsystemunitdir --without-ncurses || cat config.log

# only compile prlimit
make prlimit
mv ./prlimit $OUT_DIR

popd
