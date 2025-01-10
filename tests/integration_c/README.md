# Overview
This folder contains an SSLv2-formatted ClientHello integration test.

s2n-tls does not support SSLv2, but it does support SSLv2 formatted Client Hellos. This enables old clients (which might still support SSLv2) to negotiate newer protocols like TLS 1.2. s2n-tls will never send an SSLv2 formatted client hello, so we use an external TLS implementation to test this functionality.

## OpenSSL 1.0.2 Install
SSLv2 ClientHellos are not supported my most TLS implementation. The last version of OpenSSL to support SSLv2 ClientHellos was OpenSSL 1.0.2, and the `enable-ssl2` option must be explicitly enabled at compile time.

```
git clone https://github.com/openssl/openssl
cd openssl
git checkout OpenSSL_1_0_2-stable
./config enable-weak-ssl-ciphers enable-ssl2 --prefix=/home/ubuntu/workspace/ossl-1-0-2-install
make
make install
```

## Build Setup
This integration tests requires two separate libcrypto's to be included in the same build tree. We achieve this using s2n-tls's "interning" feature. The main libcrypto e.g. awslc, has all of it's symbols prefixed by the s2n-tls project CMake build. This allows the sslv2 test to link against a standard OpenSSL 1.0.2 libcrypto.
```
                 ┌──────────┐                 
                 │sslv2 test│                 
            ┌────┴──────────┴───┐             
            │                   │             
            │                   │             
            ▼                   ▼             
        ┌──────┐          ┌──────────────┐    
        │libs2n│          │libssl (1.0.2)│    
        └──┬───┘          └─────┬────────┘    
           │                    │             
           │                    │             
           ▼                    ▼             
┌─────────────────────┐   ┌─────────────────┐ 
│s2n_libcrypto (awslc)│   │libcrypto (1.0.2)│ 
└─────────────────────┘   └─────────────────┘ 
           ▲                                  
           │                                  
  interned/prefixed                           
           │                                  
           │                                  
  ┌────────┼────────┐                         
  │libcrypto (awslc)│                         
  └─────────────────┘                         
```


## Building the test
Because of the multiple libcryptos, this test can only be used with an _interned_ libcrypto. In the example build script below, observe that the libcrypto that s2n-tls links with is specified using `CMAKE_PREFIX_PATH`, and then the separate libcrypto used as a client is specified with `OPENSS_ROOT_DIR`.
```
rm -rf build
cmake . \
    -B build \
    -D CMAKE_C_COMPILER=clang \
    -D CMAKE_BUILD_TYPE=RelWithDebInfo \
    -D CMAKE_PREFIX_PATH=/home/ubuntu/workspace/aws-lc-install \
    -D S2N_INTERN_LIBCRYPTO=ON \
    -D OPENSSL_ROOT_DIR=/home/ubuntu/workspace/ossl-1-0-2-install
cmake --build ./build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) make -C build test ARGS="--output-on-failure"
```
