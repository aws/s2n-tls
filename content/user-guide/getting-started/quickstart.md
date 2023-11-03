+++
title = 'Quickstart'
date = 2023-10-27T19:47:06-07:00
draft = false
weight = 22
+++

This content is frequently a tutorial that goes start to finish to produce the simplest possible output with a system.

## Quickstart for Ubuntu

```sh
# clone s2n-tls
git clone https://github.com/aws/s2n-tls.git
cd s2n-tls

# install build dependencies
sudo apt update
sudo apt install cmake

# install a libcrypto
sudo apt install libssl-dev

# build s2n-tls
cmake . -Bbuild \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
cmake --build build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) ctest --test-dir build
cmake --install build
```

### And then do something

### Show how we know we did something

## Next steps

