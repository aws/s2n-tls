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


source codebuild/bin/jobs.sh

# build 2 different version of libcrypto to make it easy to break the application if
# interning doesn't work as expected
OPENSSL_1_1="$(pwd)/build/openssl_1_1"
OPENSSL_1_0="$(pwd)/build/openssl_1_0"
if [ ! -f $OPENSSL_1_0/lib/libcrypto.a ]; then
  ./codebuild/bin/install_openssl_1_0_2.sh $OPENSSL_1_0/src $OPENSSL_1_0 linux
fi
if [ ! -f $OPENSSL_1_1/lib/libcrypto.a ]; then
  ./codebuild/bin/install_openssl_1_1_1.sh $OPENSSL_1_1/src $OPENSSL_1_1 linux
fi

function fail() {
    echo "test failure: $1"
    exit 1
}

# build a default version to test what happens without interning
cmake . -Bbuild/shared-default -DCMAKE_PREFIX_PATH="$OPENSSL_1_1" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=on
cmake --build ./build/shared-default -- -j $JOBS
ldd ./build/shared-default/lib/libs2n.so | grep -q libcrypto || fail "shared-default: libcrypto was not linked"

# ensure libcrypto interning works with shared libs and no testing
cmake . -Bbuild/shared -DCMAKE_PREFIX_PATH="$OPENSSL_1_1" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=off -DS2N_INTERN_LIBCRYPTO=on
cmake --build ./build/shared -- -j $JOBS
# s2n should not publicly depend on libcrypto
ldd ./build/shared/lib/libs2n.so | grep -q libcrypto && fail "shared: libcrypto was not interned"

# ensure libcrypto interning works with shared libs and testing
cmake . -Bbuild/shared-testing -DCMAKE_PREFIX_PATH="$OPENSSL_1_1" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=on -DS2N_INTERN_LIBCRYPTO=on
cmake --build ./build/shared-testing -- -j $JOBS
# s2n should not publicly depend on libcrypto
ldd ./build/shared-testing/lib/libs2n.so | grep -q libcrypto && fail "shared-testing: libcrypto was not interned"
# run the tests and make sure they all pass with the prefixed version
make -C build/shared-testing test ARGS="-j $JOBS"
# load the wrong version of libcrypto and the tests should still pass
LD_PRELOAD=$OPENSSL_1_0/lib/libcrypto.so make -C build/shared-testing test ARGS="-j $JOBS"

# ensure libcrypto interning works with static libs
# NOTE: static builds don't vary based on testing being enabled
cmake . -Bbuild/static -DCMAKE_PREFIX_PATH="$OPENSSL_1_1" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=off -DBUILD_TESTING=on -DS2N_INTERN_LIBCRYPTO=on
cmake --build ./build/static -- -j $JOBS
make -C build/static test ARGS="-j $JOBS"

# create a small app that links against both s2n and libcrypto
cat <<EOF > build/static/app.c
#include <s2n.h>
#include <openssl/bn.h>

int main() {
    s2n_init();
    BN_CTX_new();
    return 0;
}
EOF

# ensure the small app will compile with both versions of openssl without any linking issues
for target in $OPENSSL_1_0 $OPENSSL_1_1
do
  echo "testing static linking with $target"
  mkdir -p $target/bin
  cc -fPIE -Iapi -I$target/include build/static/app.c build/static/lib/libs2n.a $target/lib/libcrypto.a -lpthread -ldl -o $target/bin/test-app
  nm $target/bin/test-app | grep -q 'T s2n$BN_CTX_new' || fail "$target: libcrypto symbols were not prefixed"
  nm $target/bin/test-app | grep -q 'T BN_CTX_new' || fail "$target: libcrypto was not linked in application"
  # make sure the app doesn't crash
  $target/bin/test-app
done

run_connection_test() {
    local TARGET="$1"
    LD_PRELOAD=$OPENSSL_1_0/lib/libcrypto.so ./build/$TARGET/bin/s2nd -c default_tls13 localhost 4433 &> /dev/null &
    local SERVER_PID=$!
    LD_PRELOAD=$OPENSSL_1_0/lib/libcrypto.so ./build/$TARGET/bin/s2nc -i -c default_tls13 localhost 4433 | tee build/client.log
    kill $SERVER_PID &> /dev/null || true

    # ensure a TLS 1.3 session was negotiated
    echo "checking for TLS 1.3"
    grep -q "Actual protocol version: 34" build/client.log
}

# without interning, the connection should fail when linking the wrong version of libcrypto
echo "running pair: TLS 1.3 failure expected"
run_connection_test shared-default && fail "TLS 1.3 handshake was expected to fail"

# with interning, the connection should succeed even though we've linked the wrong version of libcrypto
echo "running pair: TLS 1.3 success expected"
run_connection_test shared-testing || fail "TLS 1.3 handshake was expected to succeed"

echo "SUCCESS!"
