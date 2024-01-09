#!/usr/bin/env bash
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
source codebuild/bin/jobs.sh

# build 2 different version of libcrypto to make it easy to break the application if
# interning doesn't work as expected
WHICH_LIBCRYPTO=$(echo "${S2N_LIBCRYPTO:-"openssl-1.1.1"}")
TARGET_LIBCRYPTO="${WHICH_LIBCRYPTO//[-.]/_}"
TARGET_LIBCRYPTO_PATH="${TEST_DEPS_DIR}/${WHICH_LIBCRYPTO}"
OPENSSL_1_0="$OPENSSL_1_0_2_INSTALL_DIR"
if [ ! -f $OPENSSL_1_0/lib/libcrypto.a ]; then
  ./codebuild/bin/install_openssl_1_0_2.sh $OPENSSL_1_0/src $OPENSSL_1_0 linux
fi
if [ ! -f $TARGET_LIBCRYPTO_PATH/lib/libcrypto.a ]; then
  if [ "$TARGET_LIBCRYPTO" == "awslc" ]; then
    ./codebuild/bin/install_${TARGET_LIBCRYPTO}.sh $TARGET_LIBCRYPTO_PATH/src $TARGET_LIBCRYPTO_PATH 0
  else
    ./codebuild/bin/install_${TARGET_LIBCRYPTO}.sh $TARGET_LIBCRYPTO_PATH/src $TARGET_LIBCRYPTO_PATH linux
  fi
fi

COMMON_FLAGS="-DCMAKE_PREFIX_PATH=$TARGET_LIBCRYPTO_PATH -DCMAKE_BUILD_TYPE=RelWithDebInfo"
LTO_FLAGS="-DS2N_LTO=on"

# use LTO-aware commands if possible
if [ -x "$(command -v gcc-ar)" ]; then
  LTO_FLAGS+=" -DCMAKE_AR=$(which gcc-ar) -DCMAKE_NM=$(which gcc-nm) -DCMAKE_RANLIB=$(which gcc-ranlib)"
fi

function fail() {
    echo "test failure: $1"
    exit 1
}

function write_app() {
cat <<EOF > $1
#include <s2n.h>
#include <openssl/bn.h>

int main() {
    s2n_init();
    BN_CTX_new();
    return 0;
}
EOF
}

function build() {
  echo "=== BUILDING $1 ==="
  cmake . -B$1 $COMMON_FLAGS ${@:2}
  cmake --build $1 -- -j $JOBS
}

function tests() {
  echo "=== TESTING $1 ==="
  make -C $1 test ARGS="-j $JOBS -L unit"
}

##################
# Dynamic builds #
##################

# build a default version to test what happens without interning
build build/shared-default -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=on
ldd ./build/shared-default/lib/libs2n.so | grep -q libcrypto || fail "shared-default: libcrypto was not linked"

# ensure libcrypto interning works with shared libs and no testing
build build/shared -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=off -DS2N_INTERN_LIBCRYPTO=on
# s2n should not publicly depend on libcrypto
ldd ./build/shared/lib/libs2n.so | grep -q libcrypto && fail "shared: libcrypto was not interned"

# ensure libcrypto interning works with shared libs, LTO and no testing
# NOTE: interning+LTO+testing doesn't currently work
build build/shared-lto -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=off -DS2N_INTERN_LIBCRYPTO=on $LTO_FLAGS
# s2n should not publicly depend on libcrypto
ldd ./build/shared-lto/lib/libs2n.so | grep -q libcrypto && fail "shared-lto: libcrypto was not interned"

# ensure libcrypto interning works with shared libs and testing
build build/shared-testing -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=on -DS2N_INTERN_LIBCRYPTO=on
# s2n should not publicly depend on libcrypto
ldd ./build/shared-testing/lib/libs2n.so | grep -q libcrypto && fail "shared-testing: libcrypto was not interned"
# run the tests and make sure they all pass with the prefixed version
tests build/shared-testing
# load the wrong version of libcrypto and the tests should still pass
LD_PRELOAD=$OPENSSL_1_0/lib/libcrypto.so tests build/shared-testing

# ensure the small app will compile with both versions of openssl without any linking issues
for build in shared shared-lto; do
  # create a small app that links against both s2n and libcrypto
  write_app build/$build/app.c

  for target in $OPENSSL_1_0 $TARGET_LIBCRYPTO_PATH; do
    echo "testing $build linking with $target"
    mkdir -p $target/bin
    cc -fPIE -Iapi -I$target/include build/$build/app.c build/$build/lib/libs2n.so $target/lib/libcrypto.a -lpthread -ldl -o $target/bin/test-app
    # make sure the app doesn't crash
    LD_LIBRARY_PATH="build/$build/lib:$target/lib:$LD_LIBRARY_PATH" $target/bin/test-app
  done
done

##################
# Static builds  #
##################

# ensure libcrypto interning works with static libs
# NOTE: static builds don't vary based on testing being enabled
build build/static -DBUILD_SHARED_LIBS=off -DBUILD_TESTING=on -DS2N_INTERN_LIBCRYPTO=on
tests build/static

# TODO figure out how to get static-lto+interning builds working

# ensure the small app will compile with both versions of openssl without any linking issues
for build in static; do
  # create a small app that links against both s2n and libcrypto
  write_app build/$build/app.c

  for target in $OPENSSL_1_0 $TARGET_LIBCRYPTO_PATH; do
    echo "testing $build linking with $target"
    mkdir -p $target/bin
    cc -fPIE -Iapi -I$target/include build/$build/app.c build/$build/lib/libs2n.a $target/lib/libcrypto.a -lpthread -ldl -o $target/bin/test-app
    nm $target/bin/test-app | grep -q 'T s2n$BN_CTX_new' || fail "$target: libcrypto symbols were not prefixed"
    nm $target/bin/test-app | grep -q 'T BN_CTX_new' || fail "$target: libcrypto was not linked in application"
    # make sure the app doesn't crash
    $target/bin/test-app
  done
done

##################
# Runtime tests  #
##################

run_connection_test() {
    local TARGET="$1"
    
    LD_PRELOAD=$OPENSSL_1_0/lib/libcrypto.so ./build/$TARGET/bin/s2nd -c default_tls13 localhost 4433 &> /dev/null &
    local SERVER_PID=$!
    
    # Wait for the server to start up before connecting
    sleep 5s
    
    LD_PRELOAD=$OPENSSL_1_0/lib/libcrypto.so ./build/$TARGET/bin/s2nc -i -c default_tls13 localhost 4433 | tee build/client.log
    kill $SERVER_PID &> /dev/null || true

    # ensure a TLS 1.3 session was negotiated
    echo "checking for TLS 1.3"
    grep -q "Actual protocol version: 34" build/client.log
}

# without interning, the connection should fail when linking the wrong version of libcrypto
echo "Running test: attempt TLS1.3 handshake without interning"
run_connection_test shared-default && fail "TLS 1.3 handshake was expected to fail"
echo "TLS1.3 handshake failed as expected"
echo ""

# with interning, the connection should succeed even though we've linked the wrong version of libcrypto
echo "Running test: attempt TLS1.3 handshake with interning"
run_connection_test shared-testing || fail "TLS 1.3 handshake was expected to succeed"
echo "TLS1.3 handshake succeeded as expected"

echo "SUCCESS!"
