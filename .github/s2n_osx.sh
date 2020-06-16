#!/bin/bash

set -ex

# Build with debug symbols and a specific OpenSSL version
cmake -GNinja \
-DCMAKE_BUILD_TYPE=Debug \
-DCMAKE_PREFIX_PATH=/usr/local/Cellar/openssl@1.1/1.1.1g .

ninja -j2
CTEST_PARALLEL_LEVEL=2 ninja test
