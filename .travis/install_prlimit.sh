#!/bin/bash

set -e

OUT_DIR=$1

pushd $PWD

wget https://www.kernel.org/pub/linux/utils/util-linux/v2.25/util-linux-2.25.2.tar.gz
tar -xzvf util-linux-2.25.2.tar.gz
cd util-linux-2.25.2
./configure ADJTIME_PATH=/var/lib/hwclock/adjtime --disable-chfn-chsh --disable-login --disable-nologin --disable-su --disable-setpriv --disable-runuser --disable-pylibmount --disable-static --without-python --without-systemd --without-systemdsystemunitdir --without-ncurses

# only compile prlimit
make prlimit
mv ./prlimit $OUT_DIR

popd
