# Using s2n-tls

s2n-tls is a C library, and is built using Make. To clone the latest
copy of s2n-tls from git use:

```shell
git clone https://github.com/aws/s2n-tls.git
cd s2n-tls
```

## Building s2n-tls with existing libcrypto
### make Instructions
To build s2n-tls with an existing libcrypto installation, store its root folder in the
`LIBCRYPTO_ROOT` environment variable.
```shell
# /usr/local/ssl/lib should contain libcrypto.a
LIBCRYPTO_ROOT=/usr/local/ssl make
```
### CMake Instructions

Throughout this document, there are instructions for setting a `LIBCRYPTO_ROOT` environment variable, or setting install prefixes to `s2n/lib-crypto-root`. If you
are using CMake that step is unnecessary. Just follow the instructions here to use any build of libcrypto.

(Required): You need at least CMake version 3.0 to fully benefit from Modern CMake. See [this](https://www.youtube.com/watch?v=bsXLMQ6WgIk) for more information.

(Optional): Set the CMake variable `CMAKE_PREFIX_PATH` to the location libcrypto is installed to. If you do not,
the default installation on your machine will be used.

(Optional): Set the CMake variable `BUILD_SHARED_LIBS=ON` to build shared libraries. The default is static.

We recommend an out-of-source build. Suppose you have a directory `s2n` which contains the s2n-tls source code. At the same level
we can create a directory called `s2n-build`

For example, we can build and install shared libs using ninja as our build system, and the system libcrypto implementation.

````shell
mkdir s2n-build
cd s2n-build
cmake ../s2n-tls -DBUILD_SHARED_LIBS=ON -GNinja
ninja
ninja test
sudo ninja install
````

For another example, we can prepare an Xcode project using static libs using a libcrypto implementation in the directory `$HOME/s2n-user/builds/libcrypto-impl`.

````shell
mkdir s2n-build
cd s2n-build
cmake ../s2n-tls -DCMAKE_INSTALL_PREFIX=$HOME/s2n-user/builds/libcrypto-impl -G "Xcode"
# now open the project in Xcode and build from there, or use the Xcode CLI
````

Or, for unix style vanilla builds:

````shell
mkdir s2n-build
cd s2n-build
cmake ../s2n-build
make
make test
sudo make install
````

### Consuming s2n-tls via. CMake
s2n-tls ships with modern CMake finder scripts if CMake is used for the build. To take advantage of this from your CMake script, all you need to do to compile and link against s2n-tls in your project is:

````shell
find_package(s2n)

....

target_link_libraries(yourExecutableOrLibrary AWS::s2n)
````

And when invoking CMake for your project, do one of two things:
 1. Set the `CMAKE_INSTALL_PREFIX` variable with the path to your s2n-tls build.
 2. If you have globally installed s2n-tls, do nothing, it will automatically be found.

## Building s2n-tls with Openssl

We keep the build artifacts in the *-build directory:
```shell
cd libcrypto-build
```

### Download the desired Openssl version:
Openssl 3.0.5
```shell
curl -L -o openssl.tar.gz https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.5.tar.gz
tar -xzvf openssl-3.0.5.tar.gz
cd `tar ztf openssl-3.0.5.tar.gz | head -n1 | cut -f1 -d/`
```

OpenSSL-1.1.1
```shell
curl -LO https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_1_1.tar.gz
tar -xzvf OpenSSL_1_1_1.tar.gz
cd `tar ztf OpenSSL_1_1_1.tar.gz | head -n1 | cut -f1 -d/`
```

OpenSSL-1.0.2
```shell
curl -LO https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_0_2.tar.gz
tar -xzvf OpenSSL_1_0_2.tar.gz
cd `tar ztf OpenSSL_1_0_2.tar.gz | head -n1 | cut -f1 -d/`
```

### Build Openssl
The following config command disables numerous Openssl features and algorithms which are not used
by s2n-tls. A minimal feature-set can help prevent exposure to security vulnerabilities.

OpenSSL-1.1.1 and OpenSSL-3.0.5
```shell
./config -fPIC no-shared              \
        no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib     \
        no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia\
        no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng                  \
        -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
        --prefix=`pwd`/../../libcrypto-root/

make
make install
```

OpenSSL-1.0.2. Mac Users should replace "./config" with "./Configure darwin64-x86_64-cc".
```shell
./config -fPIC no-shared              \
        no-libunbound no-gmp no-jpake no-krb5 no-store    \
        no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib     \
        no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia\
        no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng                  \
        -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
        --prefix=`pwd`/../../libcrypto-root/

make depend
make
make install
```

OpenSSL-1.1.1 32-bit
```shell
setarch i386 ./config -fPIC no-shared     \
        -m32 no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib     \
        no-hw no-mdc2 no-seed no-idea no-camellia\
        no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng     \
        -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS   \
        --prefix=`pwd`/../../libcrypto-root/
```

### Build s2n-tls
```shell
cd ../../ # root of project
make
```

## Building s2n-tls with LibreSSL

To build s2n-tls with LibreSSL, do the following:

```shell
# We keep the build artifacts in the *-build directory
cd libcrypto-build

# Download the latest version of LibreSSL
curl -O http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-x.y.z.tar.gz
tar -xzvf libressl-x.y.z.tar.gz

# Build LibreSSL's libcrypto
cd libressl-x.y.z
./configure --prefix=`pwd`/../../libcrypto-root/
make CFLAGS=-fPIC install

# Build s2n-tls
cd ../../
make
```

once built, static and dynamic libraries for s2n-tls will be available in the lib/
directory.

## Building s2n-tls with BoringSSL

To build s2n-tls with BoringSSL, you must check out a copy of the BoringSSL
directly via git. This procedure has been tested with
fb68d6c901b98ffe15b8890d00bc819bf44c5f01 of BoringSSL.

```shell
# We keep the build artifacts in the *-build directory
cd libcrypto-build

# Clone BoringSSL
git clone https://boringssl.googlesource.com/boringssl

# Build BoringSSL
cd boringssl
mkdir build
cd build
cmake -DCMAKE_C_FLAGS="-fPIC" ../
make

# Copy the built library and includes
mkdir ../../../libcrypto-root/lib/
cp crypto/libcrypto.a ../../../libcrypto-root/lib/
cp -r ../include/ ../../../libcrypto-root/include

# Build s2n-tls
cd ../../../
make
```

once built, static and dynamic libraries for s2n-tls will be available in the lib/
directory.

## mlock() and system limits

Internally s2n-tls uses mlock() to prevent memory from being swapped to disk. The
s2n-tls build tests may fail in some environments where the default limit on locked
memory is too low. To check this limit, run:

```shell
ulimit -l
```

to raise the limit, consult the documentation for your platform.

### Disabling mlock()
To disable s2n-tls's mlock behavior, run your application with the `S2N_DONT_MLOCK` environment variable set.
s2n-tls also reads this for unit tests. Try `S2N_DONT_MLOCK=1 make` if you're having mlock failures during unit tests.

# s2n-tls API

The API exposed by s2n-tls is the set of functions and declarations that
are in the [s2n.h](../api/s2n.h) header file. Any functions and declarations that are in the [s2n.h](../api/s2n.h) file
are intended to be stable (API and ABI) within major version numbers of s2n-tls releases. Other functions
and structures used in s2n-tls internally can not be considered stable and their parameters, names, and
sizes may change.

The [VERSIONING.rst](../VERSIONING.rst) document contains more details about s2n's approach to versions and API changes.

## API Reference

s2n-tls uses [Doxygen](https://doxygen.nl/index.html) to document its public API. The latest s2n-tls documentation can be found on [GitHub pages](https://aws.github.io/s2n-tls/doxygen/).

Documentation for older versions or branches of s2n-tls can be generated locally. To generate the documentation, install doxygen and run `doxygen docs/doxygen/Doxyfile`. The doxygen documentation can now be found at `docs/doxygen/output/html/index.html`.

Doxygen installation instructions are available at the [Doxygen](https://doxygen.nl/download.html) webpage.

The doxygen documentation should be used in conjunction with this guide.

## Supported TLS Versions

Currently TLS 1.2 is our default version, but we recommend TLS 1.3 where possible. To use TLS 1.3 you need a security policy that supports TLS 1.3. See the [Security Policies](#security-policies) section for more information.

**Note:** s2n-tls does not support SSL2.0 for sending and receiving encrypted data, but does accept SSL2.0 hello messages.

## Error handling

s2n-tls functions that return 'int' return 0 to indicate success and -1 to indicate
failure. s2n-tls functions that return pointer types return NULL in the case of
failure. When an s2n-tls function returns a failure, s2n_errno will be set to a value
corresponding to the error. This error value can be translated into a string
explaining the error in English by calling `s2n_strerror(s2n_errno, "EN")`.
A string containing human readable error name, can be generated with `s2n_strerror_name`.
A string containing internal debug information, including filename and line number, can be generated with `s2n_strerror_debug`.
This string is useful to include when reporting issues to the s2n-tls development team.

Example:

```
if (s2n_config_set_cipher_preferences(config, prefs) < 0) {
    printf("Setting cipher prefs failed! %s : %s", s2n_strerror(s2n_errno, "EN"), s2n_strerror_debug(s2n_errno, "EN"));
    return -1;
}
```

**NOTE**: To avoid possible confusion, s2n_errno should be cleared after processing an error: `s2n_errno = S2N_ERR_T_OK`

When using s2n-tls outside of `C`, the address of the thread-local `s2n_errno` may be obtained by calling the `s2n_errno_location` function.
This will ensure that the same TLS mechanisms are used with which s2n-tls was compiled.

### Error Types

s2n-tls organizes errors into different "types" to allow applications to handle error values without catching all possibilities.
Applications using non-blocking I/O should check the error type to determine if the I/O operation failed because it would block or for some other error. To retrieve the type for a given error use `s2n_error_get_type()`.
Applications should perform any error handling logic using these high level types:

Here's an example that handles errors based on type:

```c
#define SUCCESS 0
#define FAILURE 1
#define RETRY 2

s2n_errno = S2N_ERR_T_OK;
if (s2n_negotiate(conn, &blocked) < 0) {
    switch(s2n_error_get_type(s2n_errno)) {
        case S2N_ERR_T_BLOCKED:
            /* Blocked, come back later */
            return RETRY;
        case S2N_ERR_T_CLOSED:
            return SUCCESS;
        case S2N_ERR_T_IO:
            handle_io_err(errno);
            return FAILURE;
        case S2N_ERR_T_PROTO:
            handle_proto_err();
            return FAILURE;
        case S2N_ERR_T_ALERT:
            log_alert(s2n_connection_get_alert(conn));
            return FAILURE;
        /* Everything else */
        default:
            log_other_error();
            return FAILURE;
    }
}
```

### Blinding

Blinding is a mitigation against timing side-channels which in some cases can leak information about encrypted data. By default s2n-tls will cause a thread to sleep between 10 and 30 seconds whenever tampering is detected.

Setting the `S2N_SELF_SERVICE_BLINDING` option with `s2n_connection_set_blinding()` turns off this behavior. This is useful for applications that are handling many connections in a single thread. In that case, if `s2n_recv()` or `s2n_negotiate()` return an error, self-service applications must call `s2n_connection_get_delay()` and pause activity on the connection  for the specified number of nanoseconds before calling `close()` or `shutdown()`. `s2n_shutdown()` will fail if called before the blinding delay elapses.

### Stacktraces
s2n-tls has an mechanism to capture stacktraces when errors occur.
This mechanism is off by default, but can be enabled in code by calling `s2n_stack_traces_enabled_set()`.
It can be enabled globally by setting the environment variable `S2N_PRINT_STACKTRACE=1`.

Call `s2n_print_stacktrace()` to print your stacktrace.

**Note:** Enabling stacktraces can significantly slow down unit tests, causing failures on tests (such as `s2n_cbc_verify`) that measure the timing of events.


## Initialization and Teardown

The s2n-tls library must be initialized with `s2n_init()` before calling most library functions. `s2n_init()` MUST NOT be called more than once, even when an application uses multiple threads or processes. To clean up, `s2n_cleanup()` must be called from every thread or process created after `s2n_init()` was called.

Initialization can be modified by calling `s2n_crypto_disable_init()` or `s2n_disable_atexit()` before `s2n_init()`.

An application can override s2n-tls’s internal memory management by calling `s2n_mem_set_callbacks` before calling s2n_init.

If you are trying to use FIPS mode, you must enable FIPS in your libcrypto library (probably by calling `FIPS_mode_set(1)`) before calling `s2n_init()`.

## Connection

Users will need to create a `s2n_connection` struct to store all of the state necessary for a TLS connection. Call `s2n_connection_new()` to create a new server or client connection. Call `s2n_connection_free()` to free the memory allocated for this struct when no longer needed.

### Connection Memory

The connection struct is roughly 4KB with some variation depending on how it is configured. Maintainers of the s2n-tls library carefully consider increases to the size of the connection struct as they are aware some users are memory-constrained.

A connection struct has memory allocated specifically for the TLS handshake. Memory-constrained users can free that memory by calling `s2n_connection_free_handshake()` after the handshake is successfully negotiated. Note that the handshake memory can be reused for another connection if `s2n_connection_wipe()` is called, so freeing it may result in more memory allocations later. Additionally some functions that print information about the handshake may not produce meaningful results after the handshake memory is freed.

The input and output buffers consume the most memory on the connection after the handshake. It may not be necessary to keep these buffers allocated when a connection is in a keep-alive or idle state. Call `s2n_connection_release_buffers()` to wipe and free the `in` and `out` buffers associated with a connection to reduce memory overhead of long-lived connections.

### Connection Reuse

Connection objects can be re-used across many connections to reduce memory allocation. Calling `s2n_connection_wipe()` will wipe an individual connection's state and allow the connection object to be re-used for a new TLS connection.

### Connection Info

s2n-tls provides many methods to retrieve details about the handshake and connection, such as the parameters negotiated with the peer. For a full list, see our [doxygen guide](https://aws.github.io/s2n-tls/doxygen/).

#### Protocol Version

s2n-tls provides multiple different methods to get the TLS protocol version of the connection. They should be called after the handshake has completed.
* `s2n_connection_get_actual_protocol_version()`: The actual TLS protocol version negotiated during the handshake. This is the primary value referred to as "protocol_version", and the most commonly used.
* `s2n_connection_get_server_protocol_version()`: The highest TLS protocol version the server supports.
* `s2n_connection_get_client_protocol_version()`: The highest TLS protocol version the client advertised.

## Config

`s2n_config` objects are used to change the default settings of a s2n-tls connection. Use `s2n_config_new()` to create a new config object and `s2n_config_free()` to free the object when no longer needed. It is not necessary to create a config object per connection; one config object can be used for many connections. To associate a connection with a config call `s2n_connection_set_config()`. Most commonly, a `s2n_config` object is used to set the certificate key pair for authentication and alter the list of cipher suite preferences. See the sections for [certificates](#certificates-and-authentication) and [security policies](#security-policies) for more information on those settings.

### Overriding the Config

Some `s2n_config` settings can be overridden on a specific connection if desired. For example, `s2n_config_append_protocol_preference()` appends a list of ALPN protocols to a `s2n_config`. Calling the `s2n_connection_append_protocol_preference()` API will override the list of ALPN protocols for an individual connection. Not all config APIs have a corresponding connection API so if there is one missing contact us with an explanation on why it is required for your use-case.

## Security Policies

s2n-tls uses pre-made security policies to help avoid common misconfiguration mistakes for TLS.

`s2n_config_set_cipher_preferences()` sets a security policy, which includes the cipher/kem/signature/ecc preferences and protocol version.

The following chart maps the security policy version to protocol version and ciphersuites supported:

|    version     | SSLv3 | TLS1.0 | TLS1.1 | TLS1.2 | TLS1.3  | AES-CBC | ChaCha20-Poly1305 | ECDSA | AES-GCM | 3DES | RC4 | DHE | ECDHE |
|----------------|-------|--------|--------|--------|---------|---------|-------------------|-------|---------|------|-----|-----|-------|
|   "default"    |       |   X    |    X   |    X   |         |    X    |          X        |       |    X    |      |     |     |   X   |
|   "20190214"   |       |   X    |    X   |    X   |         |    X    |                   |   X   |    X    |  X   |     |  X  |   X   |
|   "20170718"   |       |   X    |    X   |    X   |         |    X    |                   |       |    X    |      |     |     |   X   |
|   "20170405"   |       |   X    |    X   |    X   |         |    X    |                   |       |    X    |  X   |     |     |   X   |
|   "20170328"   |       |   X    |    X   |    X   |         |    X    |                   |       |    X    |  X   |     |  X  |   X   |
|   "20170210"   |       |   X    |    X   |    X   |         |    X    |          X        |       |    X    |      |     |     |   X   |
|   "20160824"   |       |   X    |    X   |    X   |         |    X    |                   |       |    X    |      |     |     |   X   |
|   "20160804"   |       |   X    |    X   |    X   |         |    X    |                   |       |    X    |  X   |     |     |   X   |
|   "20160411"   |       |   X    |    X   |    X   |         |    X    |                   |       |    X    |  X   |     |     |   X   |
|   "20150306"   |       |   X    |    X   |    X   |         |    X    |                   |       |    X    |  X   |     |     |   X   |
|   "20150214"   |       |   X    |    X   |    X   |         |    X    |                   |       |    X    |  X   |     |  X  |       |
|   "20150202"   |       |   X    |    X   |    X   |         |    X    |                   |       |         |  X   |     |  X  |       |
|   "20141001"   |       |   X    |    X   |    X   |         |    X    |                   |       |         |  X   |  X  |  X  |       |
|   "20140601"   |   X   |   X    |    X   |    X   |         |    X    |                   |       |         |  X   |  X  |  X  |       |
|   "20190120"   |       |   X    |    X   |    X   |         |    X    |                   |       |    X    |  X   |     |     |   X   |
|   "20190121"   |       |   X    |    X   |    X   |         |    X    |                   |       |    X    |  X   |     |     |   X   |
|   "20190122"   |       |   X    |    X   |    X   |         |    X    |                   |   X   |    X    |  X   |     |  X  |   X   |
| "default_tls13"|       |   X    |    X   |    X   |    X    |    X    |          X        |   X   |    X    |      |     |     |   X   |
|   "20190801"   |       |   X    |    X   |    X   |    X    |    X    |          X        |       |    X    |      |     |     |   X   |
|   "20190802"   |       |   X    |    X   |    X   |    X    |    X    |          X        |       |    X    |      |     |     |   X   |
|   "20200207"   |       |   X    |    X   |    X   |    X    |    X    |          X        |       |    X    |      |     |     |       |
|   "rfc9151"    |       |        |        |    X   |    X    |         |                   |   X   |    X    |      |     |  X  |   X   |

The "default" and "default_tls13" version is special in that it will be updated with future s2n-tls changes and ciphersuites and protocol versions may be added and removed, or their internal order of preference might change. Numbered versions are fixed and will never change.

"20160411" follows the same general preference order as "default". The main difference is it has a CBC cipher suite at the top. This is to accommodate certain Java clients that have poor GCM implementations. Users of s2n-tls who have found GCM to be hurting performance for their clients should consider this version.

"20170405" is a FIPS compliant cipher suite preference list based on approved algorithms in the [FIPS 140-2 Annex A](http://csrc.nist.gov/publications/fips/fips140-2/fips1402annexa.pdf). Similarly to "20160411", this preference list has CBC cipher suites at the top to accommodate certain Java clients. Users of s2n-tls who plan to enable FIPS mode should consider this version.

The "rfc9151" security policy is derived from [Commercial National Security Algorithm (CNSA) Suite Profile for TLS and DTLS 1.2 and 1.3](https://datatracker.ietf.org/doc/html/rfc9151).

s2n-tls does not expose an API to control the order of preference for each ciphersuite or protocol version. s2n-tls follows the following order:

*NOTE*: All ChaCha20-Poly1305 cipher suites will not be available if s2n-tls is not built with an Openssl 1.1.1 libcrypto. The
underlying encrypt/decrypt functions are not available in older versions.

1. Always prefer the highest protocol version supported
2. Always use forward secrecy where possible. Prefer ECDHE over DHE.
3. Prefer encryption ciphers in the following order: AES128, AES256, ChaCha20, 3DES, RC4.
4. Prefer record authentication modes in the following order: GCM, Poly1305, SHA256, SHA1, MD5.

The following chart maps the security policy version to the signature scheme supported:

|    version     |   RSA PKCS1  |   ECDSA  |  SHA-1 Legacy |  RSA PSS |
|----------------|--------------|----------|---------------|----------|
|   "default"    |      X       |     X    |      X        |          |
|   "20190214"   |      X       |     X    |      X        |          |
|   "20170718"   |      X       |     X    |      X        |          |
|   "20170405"   |      X       |     X    |      X        |          |
|   "20170328"   |      X       |     X    |      X        |          |
|   "20170210"   |      X       |     X    |      X        |          |
|   "20160824"   |      X       |     X    |      X        |          |
|   "20160804"   |      X       |     X    |      X        |          |
|   "20160411"   |      X       |     X    |      X        |          |
|   "20150306"   |      X       |     X    |      X        |          |
|   "20150214"   |      X       |     X    |      X        |          |
|   "20150202"   |      X       |     X    |      X        |          |
|   "20141001"   |      X       |     X    |      X        |          |
|   "20140601"   |      X       |     X    |      X        |          |
|   "20190120"   |      X       |     X    |      X        |          |
|   "20190121"   |      X       |     X    |      X        |          |
|   "20190122"   |      X       |     X    |      X        |          |
| "default_tls13"|      X       |     X    |      X        |    X     |
|   "20190801"   |      X       |     X    |      X        |    X     |
|   "20190802"   |      X       |     X    |      X        |    X     |
|   "20200207"   |      X       |     X    |      X        |    X     |
|   "rfc9151"    |      X       |     X    |               |    X     |

Note that the default_tls13 security policy will never support legacy SHA-1 algorithms in TLS1.3, but will support
legacy SHA-1 algorithms in CertificateVerify messages if TLS1.2 has been negotiated.

The following chart maps the security policy version to the supported curves/groups:

|    version     |   secp256r1  |  secp384r1 | x25519 |
|----------------|--------------|------------|--------|
|   "default"    |      X       |      X     |        |
|   "20190214"   |      X       |      X     |        |
|   "20170718"   |      X       |      X     |        |
|   "20170405"   |      X       |      X     |        |
|   "20170328"   |      X       |      X     |        |
|   "20170210"   |      X       |      X     |        |
|   "20160824"   |      X       |      X     |        |
|   "20160804"   |      X       |      X     |        |
|   "20160411"   |      X       |      X     |        |
|   "20150306"   |      X       |      X     |        |
|   "20150214"   |      X       |      X     |        |
|   "20150202"   |      X       |      X     |        |
|   "20141001"   |      X       |      X     |        |
|   "20140601"   |      X       |      X     |        |
|   "20190120"   |      X       |      X     |        |
|   "20190121"   |      X       |      X     |        |
|   "20190122"   |      X       |      X     |        |
| "default_tls13"|      X       |      X     |   X    |
|   "20190801"   |      X       |      X     |   X    |
|   "20190802"   |      X       |      X     |        |
|   "20200207"   |      X       |      X     |   X    |
|   "rfc9151"    |              |      X     |        |

## Certificates and Authentication

TLS uses certificates to authenticate the server (and optionally the client). The handshake will fail if the client cannot verify the server’s certificate.

Authentication is usually the most expensive part of the handshake. To avoid the cost, consider using [session resumption](#session-resumption) or [pre-shared keys](#tls13-pre-shared-key-related-calls).

### Configuring the Trust Store

To validate the peer’s certificate, the local “trust store” must contain a certificate that can authenticate the peer’s certificate.

By default, s2n-tls will be initialized with the common trust store locations for the host operating system. To completely override those locations, call `s2n_config_wipe_trust_store()`. To add certificates to the trust store, call `s2n_config_set_verification_ca_location()` or `s2n_config_add_pem_to_trust_store()`.

### Server Authentication

A server must have a certificate and private key pair to prove its identity. s2n-tls supports RSA, RSA-PSS, and ECDSA certificates, and allows one of each type to be added to a config.

Create a new certificate and key pair by calling `s2n_cert_chain_and_key_new()`, then load the pem-encoded data with `s2n_cert_chain_and_key_load_pem_bytes()`.  Call `s2n_config_add_cert_chain_and_key_to_store()` to add the certificate and key pair to the config. When a certificate and key pair is no longer needed, it must be cleaned up with `s2n_cert_chain_and_key_free()`.

A client can add restrictions on the certificate’s hostname by setting a custom `s2n_verify_host_fn` with `s2n_config_set_verify_host_callback()` or `s2n_connection_set_verify_host_callback()`. The default behavior is to require that the hostname match the server name set with `s2n_set_server_name()`.

### Client / Mutual Authentication

Client authentication is not enabled by default. However, the server can require that the client also provide a certificate, if the server needs to authenticate clients before accepting connections.

Client authentication can be configured by calling `s2n_config_set_client_auth_type()` or `s2n_connection_set_client_auth_type()` for both the client and server. Additionally, the client will need to load a certificate and key pair as described for the server in [Server Authentication](#server-authentication) and the server will need to configure its trust store as described in [Configuring the Trust Store](#configuring-the-trust-store).

When using client authentication, the server MUST implement the `s2n_verify_host_fn`, because the default behavior will likely reject all client certificates.

### Certificate Inspection

Applications may want to know which certificate was used by a server for authentication during a connection, since servers can set multiple certificates. `s2n_connection_get_selected_cert()` will return the local certificate chain object used to authenticate. `s2n_connection_get_peer_cert_chain()` will provide the peer's certificate chain, if they sent one. Use `s2n_cert_chain_get_length()` and `s2n_cert_chain_get_cert()` to parse the certificate chain object and get a single certificate from the chain. Use `s2n_cert_get_der()` to get the DER encoded certificate if desired.

Additionally s2n-tls has functions for parsing certificate extensions on a certificate. Use `s2n_cert_get_x509_extension_value_length()` and `s2n_cert_get_x509_extension_value()` to obtain a specific DER encoded certificate extension from a certificate. `s2n_cert_get_utf8_string_from_extension_data_length()` and `s2n_cert_get_utf8_string_from_extension_data()` can be used to obtain a specific UTF8 string representation of a certificate extension instead. These functions will work for both RFC-defined certificate extensions and custom certificate extensions.

### OCSP Stapling

Online Certificate Status Protocol (OCSP) is a protocol to establish whether or not a certificate has been revoked. The requester (usually a client), asks the responder (usually a server), to ‘staple’ the certificate status information along with the certificate itself. The certificate status sent back will be either expired, current, or unknown, which the requester can use to determine whether or not to accept the certificate.

OCSP stapling can be applied to both client and server certificates when using TLS1.3, but only to server certificates when using TLS1.2.

To use OCSP stapling, both server and client must call `s2n_config_set_status_request_type()` with S2N_STATUS_REQUEST_OCSP. The server (or client, if using client authentication) will also need to call `s2n_cert_chain_and_key_set_ocsp_data()` to set the raw bytes of the OCSP stapling data.

The OCSP stapling information will be automatically validated if the underlying libcrypto supports OCSP validation. `s2n_config_set_check_stapled_ocsp_response()` can be called with "0" to turn this off. Call `s2n_connection_get_ocsp_response()` to retrieve the received OCSP stapling information for manual verification.

### Certificate Transparency

Certificate transparency is a framework to store public logs of CA-issued certificates. If requested, certificate owners can send a signed certificate timestamp (SCT) to prove that their certificate exists in these logs. The requester can choose whether or not to accept a certificate based on this information.

Certificate transparency information can be applied to both client and server certificates when using TLS1.3, but only to server certificates when using TLS1.2.

To use certificate transparency, the requester (usually the client) must call `s2n_config_set_ct_support_level()` with S2N_CT_SUPPORT_REQUEST. The responder (usually the server) must call `s2n_cert_chain_and_key_set_sct_list()` to set the raw bytes of the transparency information.

Call `s2n_connection_get_sct_list()` to retrieve the received certificate transparency information. The format of this data is the SignedCertificateTimestampList structure defined in section 3.3 of RFC 6962.

## Session Resumption

TLS handshake sessions are CPU-heavy due to the calculations involved in authenticating a certificate. These calculations can be skipped after the first connection by turning on session resumption. This mechanism stores state from the previous session and uses it to establish the next session, allowing the handshake to skip the costly authentication step while keeping the same cryptographic guarantees. The authentication step can be skipped because both the server and client will use their possession of the key from the previous session to prove who they are. We usually refer to the stored session state as a "session ticket". Note that this session ticket is encrypted by the server, so a server will have to set up an external key in order to do session resumption.

### Session Ticket Key

The key that encrypts and decrypts the session state is not related to the keys negotiated as part of the TLS handshake and has to be set by the server by calling `s2n_config_add_ticket_crypto_key()`. See [RFC5077](https://www.rfc-editor.org/rfc/rfc5077#section-5.5) for guidelines on securely generating keys.

Each key has two different expiration dates. The first expiration date signifies the time that the key can be used for both encryption and decryption. The second expiration date signifies the time that the key can be used only for decryption. This mechanism is to ensure that a session ticket can be successfully decrypted if it was encrypted by a key that was about to expire. The full lifetime of the key is therefore the encrypt-decrypt lifetime plus the decrypt-only lifetime. To alter the default key lifetime call `s2n_config_set_ticket_encrypt_decrypt_key_lifetime()` and `s2n_config_set_ticket_decrypt_key_lifetime()`.

The server will stop issuing session resumption tickets if a user doesn't set up a new key before the previous key passes through its encrypt-decrypt lifetime. Therefore it is recommended to add a new key when half of the previous key's encrypt-decrypt lifetime has passed.

### Stateless Session Resumption

In stateless session resumption the server sends a session ticket to a client after a successful handshake, and the client can send that ticket back to the server during a new connection to skip the authentication step. This mechanism allows servers to avoid storing individual state for each client, and for that reason is the preferred method for resuming a session.

Servers should call `s2n_config_set_session_tickets_onoff()` to enable stateless session resumption. Additionally the server needs to set up an encryption key using `s2n_config_add_ticket_crypto_key()`.

Clients should call `s2n_config_set_session_tickets_onoff()` to enable stateless session resumption and set a session ticket callback function using `s2n_config_set_session_ticket_cb()`, which will allow clients to receive a session ticket when it arrives. Then `s2n_connection_set_session()` should be called with that saved ticket when attempting to resume a new connection.

### Stateful Session Resumption

In stateful session resumption, also known as session caching, the server caches the session state per client and resumes a session based on the client's session ID. Note that session caching has not been implemented for > TLS1.2. If stateful session resumption is turned on and a TLS1.3 handshake is negotiated, the caching mechanism will not store that session and resumption will not be available the next time the client connects.

Servers should set the three caching callback functions: `s2n_config_set_cache_store_callback()`, `s2n_config_set_cache_retrieve_callback()`, and `s2n_config_set_cache_delete_callback()` and then call `s2n_config_set_session_cache_onoff()` to enable stateful session resumption. Session caching will not be turned on unless all three session cache callbacks are set prior to calling `s2n_config_set_session_cache_onoff()`. Additionally, the server needs to set up an encryption key using `s2n_config_add_ticket_crypto_key()`.

Clients should call `s2n_connection_get_session()` to retrieve some serialized state about the session. Then `s2n_connection_set_session()` should be called with that saved state when attempting to resume a new connection.

### Session Resumption in TLS1.2 and TLS1.3

In TLS1.2, session ticket messages are sent during the handshake and are automatically received as part of calling `s2n_negotiate()`. They will be available as soon as negotiation is complete.

In TLS1.3, session ticket messages are sent after the handshake as "post-handshake" messages, and may not be received as part of calling `s2n_negotiate()`. A s2n-tls server will send tickets immediately after the handshake, so clients can receive them by calling `s2n_recv()` immediately after the handshake completes. However, other server implementations may send their session tickets later, at any time during the connection.

Additionally, in TLS1.3, multiple session tickets may be issued for the same connection. Servers can call `s2n_config_set_initial_ticket_count()` to set the number of tickets they want to send and `s2n_connection_add_new_tickets_to_send()` to increase the number of tickets to send during a connection.

### s2n\_config\_set\_client\_hello\_cb

```c
int s2n_config_set_client_hello_cb(struct s2n_config *config, s2n_client_hello_fn client_hello_callback, void *ctx);
```

**s2n_config_set_client_hello_cb** allows the caller to set a callback function
that will be called after ClientHello was parsed.

```c
typedef int s2n_client_hello_fn(struct s2n_connection *conn, void *ctx);
```

The callback function takes a s2n-tls connection as input, which receives the
ClientHello and the context previously provided in **s2n_config_set_client_hello_cb**.
The callback can access any ClientHello information from the connection and use
the **s2n_connection_set_config** call to change the config of the connection.

```c
int s2n_config_set_client_hello_cb_mode(struct s2n_config *config, s2n_client_hello_cb_mode cb_mode);
```
Sets the callback execution mode.

The callback can be be invoked in two modes
- **S2N_CLIENT_HELLO_CB_BLOCKING** (default):

    In this mode s2n-tls expects the callback to complete its work
    and return the appropriate response code before the handshake continues.
    If any of the connection properties were changed based on the server_name
    extension the callback must either return a value greater than 0 or invoke **s2n_connection_server_name_extension_used**,
    otherwise the callback returns 0 to continue the handshake.

- **S2N_CLIENT_HELLO_CB_NONBLOCKING**:

    In non-blocking mode, s2n-tls expects the callback to not complete its work. If the callback
    returns a response code of 0 s2n-tls will return **S2N_FAILURE** with **S2N_ERR_T_BLOCKED**
    error type and **s2n_blocked_status** set to **S2N_BLOCKED_ON_APPLICATION_INPUT**.
    The handshake is paused and further calls to **s2n_negotiate** will continue to return the
    same error until **s2n_client_hello_cb_done** is invoked for the **s2n_connection** to resume
    the handshake. This allows s2n-tls clients to process client_hello without
    blocking and then resume the handshake at a later time.
    If any of the connection properties were changed on the basis of the server_name extension then
    **s2n_connection_server_name_extension_used** must be invoked before marking the callback done.

The callback can return a negative value to make s2n-tls terminate the
handshake early with a fatal handshake failure alert.

```c
int s2n_client_hello_cb_done(struct s2n_connection *conn)
```
Marks the non-blocking callback as complete.
Can be invoked from within the callback when operating in non-blocking mode
to continue the handshake.

```c
int s2n_client_server_name_used(struct s2n_connection *conn)
```
Indicates that connection properties were changed on the basis of server_name.
Triggers a s2n-tls server to send the server_name extension. Must be called
before s2n-tls finishes processing the ClientHello.

## Record sizes

### Throughput vs Latency

When sending data, s2n-tls uses a default maximum record size which experimentation
has suggested provides a reasonable balance of performance and throughput.

**s2n_connection_prefer_throughput** can be called to increase the record size, which
minimizes overhead. It also increases s2n-tls's memory usage.

**s2n_connection_prefer_low_latency** can be called to decrease the record size, which
allows the receiver to decrypt the data faster. It also decreases s2n-tls's memory usage.

These options only affect the size of the records that s2n-tls sends, not the behavior
of the peer.

### Maximum Fragment Length

The maximum number of bytes that can be sent in a TLS record is called the "maximum fragment length",
and is set to 2^14 bytes by default. Regardless of the maximum record size that s2n-tls
uses when sending, it may receive records containing up to 2^14 bytes of plaintext.

A client can request a lower maximum fragment length by calling **s2n_config_send_max_fragment_length**,
reducing the size of TLS records sent and providing benefits similar to **s2n_connection_prefer_low_latency**.
However, many TLS servers either ignore these requests or handle them incorrectly, so a client should
never assume that a lower maximum fragment length will be honored. If a server accepts the requested
maximum fragment length, the client will respect that maximum when sending.

By default, an s2n-tls server will ignore a client's requested maximum fragment length.
If **s2n_config_accept_max_fragment_length** is called, the server will respect the client's requested
maximum fragment length when sending, but will not reject client records with a larger fragment size.

If a maximum fragment length is negotiated during the connection, it will override the behavior
configured by **s2n_connection_prefer_throughput** and **s2n_connection_prefer_low_latency**.

### Dynamic Record Sizing

Sending smaller records at the beginning of a connection can decrease first byte latency,
particularly if TCP slow start is used.

**s2n_connection_set_dynamic_record_threshold** can be called to initially send smaller records.
The connection will send the first **resize_threshold** bytes in records small enough to
fit in a single standard 1500 byte ethernet frame. Whenever **timeout_threshold** seconds
pass without sending data, the connection will revert to this behavior and send small records again.

Dynamic record sizing doesn't completely override **s2n_connection_prefer_throughput**,
**s2n_connection_prefer_low_latency**, or the negotiated maximum fragment length.
Once **resize_threshold** is hit, records return to the maximum size configured for the connection.
And if the maximum fragment length negotiated with the peer is lower than what dynamic record sizing
would normally produce, the lower value will be used.

## Connection-oriented functions

### s2n\_connection\_set\_fd

```c
int s2n_connection_set_fd(struct s2n_connection *conn,
                          int readfd);
int s2n_connection_set_read_fd(struct s2n_connection *conn,
                               int readfd);
int s2n_connection_set_write_fd(struct s2n_connection *conn,
                                int writefd);
```

**s2n_connection_set_fd** sets the file-descriptor for an s2n-tls connection. This
file-descriptor should be active and connected. s2n-tls also supports setting the
read and write file-descriptors to different values (for pipes or other unusual
types of I/O).

**Important Note:**
If the read end of the pipe is closed unexpectedly, writing to the pipe will raise
a SIGPIPE signal. **s2n-tls does NOT handle SIGPIPE.** A SIGPIPE signal will cause
the process to terminate unless it is handled or ignored by the application.

### s2n\_connection\_get\_client\_hello

```c
struct s2n_client_hello *s2n_connection_get_client_hello(struct s2n_connection *conn);
```
For a given s2n_connection, **s2n_connection_get_client_hello** returns a handle
to the s2n_client_hello structure holding the client hello message sent by the client during the handshake.
NULL is returned if the connection has not yet received and parsed the client hello.
Earliest point during the handshake when this structure is available for use is in the client_hello_callback (see **s2n_config_set_client_hello_cb**).

### s2n\_client\_hello\_get\_raw\_message

```c
ssize_t s2n_client_hello_get_raw_message_length(struct s2n_client_hello *ch);
ssize_t s2n_client_hello_get_raw_message(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length);
```

- **ch** The s2n_client_hello on the s2n_connection. The handle can be obtained using **s2n_connection_get_client_hello**.
- **out** Pointer to a buffer into which the raw client hello bytes should be copied.
- **max_length** Max number of bytes to copy into the **out** buffer.

**s2n_client_hello_get_raw_message_length** returns the size of the ClientHello message received by the server; it can be used to allocate the **out** buffer.
**s2n_client_hello_get_raw_message** copies **max_length** bytes of the ClientHello message into the **out** buffer and returns the number of copied bytes.
The ClientHello instrumented using this function will have the Random bytes zero-ed out.

For SSLv2 ClientHello messages, the raw message contains only the cipher_specs, session_id and members portions of the hello message
(see [RFC5246](https://tools.ietf.org/html/rfc5246#appendix-E.2)). To access other members, you may use the
**s2n_connection_get_client_hello_version**, **s2n_connection_get_client_protocol_version**  and **s2n_connection_get_session_id_length** accesor functions.

### s2n\_client\_hello\_get\_cipher\_suites

```c
ssize_t s2n_client_hello_get_cipher_suites_length(struct s2n_client_hello *ch);
ssize_t s2n_client_hello_get_cipher_suites(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length);
```

- **ch** The s2n_client_hello on the s2n_connection. The handle can be obtained using **s2n_connection_get_client_hello**.
- **out** Pointer to a buffer into which the cipher_suites bytes should be copied.
- **max_length** Max number of bytes to copy into the **out** buffer.

**s2n_client_hello_get_cipher_suites_length** returns the number of bytes the cipher_suites takes on the ClientHello message received by the server; it can be used to allocate the **out** buffer.
**s2n_client_hello_get_cipher_suites** copies into the **out** buffer **max_length** bytes of the cipher_suites on the ClientHello and returns the number of copied bytes.

### s2n\_client\_hello\_get\_extensions

```c
ssize_t s2n_client_hello_get_extensions_length(struct s2n_client_hello *ch);
ssize_t s2n_client_hello_get_extensions(struct s2n_client_hello *ch, uint8_t *out, uint32_t max_length);
```

- **ch** The s2n_client_hello on the s2n_connection. The handle can be obtained using **s2n_connection_get_client_hello**.
- **out** Pointer to a buffer into which the cipher_suites bytes should be copied.
- **max_length** Max number of bytes to copy into the **out** buffer.

**s2n_client_hello_get_extensions_length** returns the number of bytes the extensions take on the ClientHello message received by the server; it can be used to allocate the **out** buffer.
**s2n_client_hello_get_extensions** copies into the **out** buffer **max_length** bytes of the extensions on the ClientHello and returns the number of copied bytes.

### s2n\_client\_hello\_get\_extension

```c
ssize_t s2n_client_hello_get_extension_length(struct s2n_client_hello *ch, s2n_tls_extension_type extension_type);
ssize_t s2n_client_hello_get_extension_by_id(struct s2n_client_hello *ch, s2n_tls_extension_type extension_type, uint8_t *out, uint32_t max_length);
```

- **ch** The s2n_client_hello on the s2n_connection. The handle can be obtained using **s2n_connection_get_client_hello**.
- **s2n_tls_extension_type** Enum [s2n_tls_extension_type](#s2n\_config\_set\_extension\_data) lists all supported extension types.
- **out** Pointer to a buffer into which the extension bytes should be copied.
- **max_length** Max number of bytes to copy into the **out** buffer.

**s2n_client_hello_get_extension_length** returns the number of bytes the given extension type takes on the ClientHello message received by the server; it can be used to allocate the **out** buffer.
**s2n_client_hello_get_extension_by_id** copies into the **out** buffer **max_length** bytes of a given extension type on the ClientHello and returns the number of copied bytes.

### s2n\_client\_hello\_get\_session\_id

```c
int s2n_client_hello_get_session_id_length(struct s2n_client_hello *ch, uint32_t *out_length);
int s2n_client_hello_get_session_id(struct s2n_client_hello *ch, uint8_t *out, uint32_t *out_length, uint32_t max_length);
```

These functions retrieve the session id as sent by the client in the ClientHello message. The session id on the **s2n_connection** may change later when the server sends the ServerHello; see **s2n_connection_get_session_id** for how to get the final session id used for future session resumption.

**s2n_client_hello_get_session_id_length** stores the ClientHello session id length in bytes in **out_length**. The **ch** is a pointer to **s2n_client_hello** of the **s2n_connection** which can be obtained using **s2n_connection_get_client_hello**. The **out_length** can be used to allocate the **out** buffer for the **s2n_client_hello_get_session_id** call.

**s2n_client_hello_get_session_id** copies up to **max_length** bytes of the ClientHello session_id into the **out** buffer and stores the number of copied bytes in **out_length**.

## Private Key Operation Related Calls

By default, s2n-tls automatically uses the configured private key to synchronously perform the signature
and decryption operations required for a tls handshake. However, this default behavior may not
work for some situations.

For example:
* An application may want to perform the CPU-expensive signature and decryption operations
asynchronously to avoid blocking the main event loop.
See [Asynchronous private key operations](#Asynchronous-private-key-operations)
* An application may not have direct access to the private key, such as when using PKCS#11.
See [Offloading private key operations](#Offloading-private-key-operations)

To handle these use cases, s2n-tls provides a callback to allow users to control how these operations
are performed. The callback is set via **s2n_config_set_async_pkey_callback** and is triggered
every time **s2n_negotiate** performs an action involving the private key. The callback is passed
**op**, an opaque object representing the private key operation. To avoid memory leaks, **op** must
always eventually be freed by calling **s2n_async_pkey_op_free**.

The private key operation can be performed by calling **s2n_async_pkey_op_perform**
(or **s2n_async_pkey_op_set_output**: see [Offloading private key operations](#Offloading-private-key-operations)).
The required private key can be retrieved using the **s2n_connection_get_selected_cert** and **s2n_cert_chain_and_key_get_private_key** calls. The operation can then be finalized with **s2n_async_pkey_op_apply** to continue the handshake.

### Asynchronous Private Key Operations

When s2n-tls is used in non-blocking mode, private key operations can be completed
asynchronously. This model can be useful to move execution of
CPU-heavy private key operations out of the main
event loop, preventing **s2n_negotiate** from blocking the loop for a few
milliseconds each time the private key operation needs to be performed.

To handle private key operations asynchronously, return from the callback without calling
**s2n_async_pkey_op_perform** or **s2n_async_pkey_op_apply**. Usually the user would do this
by spawning a separate thread to perform **op** and immediately returning **S2N_SUCCESS**
from the callback without waiting for that separate thread to complete. In response,
**s2n_negotiate** will return **S2N_FAILURE** with an error of type **S2N_ERR_T_BLOCKED**
and **s2n_blocked_status** set to **S2N_BLOCKED_ON_APPLICATION_INPUT**.
All subsequent calls to **s2n_negotiate** will produce the same result until **s2n_async_pkey_op_apply**
is called to finalize the **op**.

Note: It is not safe to call multiple functions on the same **conn** or
**op** objects from 2 different threads at the same time. Doing so will
produce undefined behavior. However it is safe to have a call to a
function involving only **conn** at the same time as a call to a
function involving only **op**, as those objects are not coupled with
each other. It is also safe to free **conn** or **op** at any moment with
respective function calls, with the exception that **conn** cannot
be freed inside the **s2n_async_pkey_fn** callback.

### Synchronous Private Key Operations

Despite the "async" in the function names, private key operations can also be completed synchronously using the callback.
To complete an operation synchronously, simply call **s2n_async_pkey_op_perform** and **s2n_async_pkey_op_apply** inside the callback.
If the callback succeeds, the handshake will continue uninterrupted.
If the callback fails, **s2n_negotiate** will fail with an error of type **S2N_ERR_T_INTERNAL**.

### Offloading Private Key Operations

The **s2n_async_pkey_op_perform** call used to perform a private key operation requires
direct access to the private key. In some cases, like when using PKCS#11, users may not
have access to the private key. In these cases, we can substitute **s2n_async_pkey_op_set_output**
for **s2n_async_pkey_op_perform** to tell s2n-tls the result of the operation rather than
having s2n-tls perform the operation itself.

s2n-tls provides a number of calls to gather the information necessary for
an outside module or library to perform the operation. The application can query the type of private
key operation by calling **s2n_async_pkey_op_get_op_type**. In order to perform
an operation, the application must ask s2n-tls to copy the operation's input into an
application supplied buffer. The appropriate buffer size can be determined by calling
**s2n_async_pkey_op_get_input_size**. Once a buffer of the proper size is
allocated, the application can request the input data by calling **s2n_async_pkey_op_get_input**.
After the operation is completed, the finished output can be copied back to S2N by calling **s2n_async_pkey_op_set_output**.
Once the output is set, the private key operation can be completed by calling **s2n_async_pkey_op_apply** as usual.

Offloading can be performed either synchronously or asynchronously. If the offloaded operation
fails synchronously, simply return S2N_FAILURE from the callback. If the offloaded operation
fails asynchronously, s2n-tls does not provide a way to communicate that result. Instead,
simply shutdown and cleanup the connection as you would for any other error.

## TLS1.3 Pre-Shared Key Related Calls

s2n-tls supports pre-shared keys (PSKs) as of TLS1.3. PSKs allow users to establish secrets outside of the handshake, skipping certificate exchange and authentication.

### Benefits of Using Pre-Shared Keys

Using pre-shared keys can avoid the need for public key operations. This is useful in performance-constrained environments with limited CPU power. PSKs may also be more convenient from a key management point of view: If the system already has a mechanism for sharing secrets, that mechanism can be reused for TLS PSKs.

### Security Considerations

A PSK must not be shared between more than one server and one client. An entity that acts as both a server and a client should not use the same PSK for both roles. For more information see: [Selfie: reflections on TLS 1.3 with PSK.](https://eprint.iacr.org/2019/347.pdf)


### Configuring External Pre-Shared Keys

Use the following APIs to configure external pre-shared keys.

```c
struct s2n_psk* s2n_external_psk_new();
int s2n_psk_free(struct s2n_psk **psk);
int s2n_psk_set_identity(struct s2n_psk *psk, const uint8_t *identity, uint16_t identity_size);
int s2n_psk_set_secret(struct s2n_psk *psk, const uint8_t *secret, uint16_t secret_size);
int s2n_psk_set_hmac(struct s2n_psk *psk, s2n_psk_hmac hmac);
int s2n_connection_append_psk(struct s2n_connection *conn, struct s2n_psk *psk);
int s2n_config_set_psk_mode(struct s2n_config *config, s2n_psk_mode mode);
int s2n_connection_set_psk_mode(struct s2n_connection *conn, s2n_psk_mode mode);
```

**s2n_external_psk_new** creates a new external PSK object with **S2N_PSK_HMAC_SHA256** as the default PSK hmac algorithm. Use **s2n_psk_free** to free the memory allocated to the external PSK object.

**s2n_psk_set_identity** sets the identity for a given PSK. The identity is a unique identifier for the pre-shared secret. This identity is transmitted over the network unencrypted and is a non-secret value, therefore do not include any confidential information.

**s2n_psk_set_secret** sets the secret value for a given PSK. Deriving a shared secret from a password or other low-entropy source is not secure and is subject to dictionary attacks.

**s2n_psk_set_hmac** sets the PSK hmac algorithm for a given PSK. The supported PSK hmac algorithms are listed in the **s2n_psk_hmac** enum. This API overrides the default PSK hmac algorithm value of **S2N_PSK_HMAC_SHA256** and may influence the server cipher suite selection.

**s2n_connection_append_psk** appends the PSK to the connection. Both server and client should call this API to add PSKs to their connection. The order this API is called matters, as PSKs that are appended first will be more preferred than PSKs appended last. This API must be called prior to the server selecting a PSK for the connection.

**s2n_config_set_psk_mode** configures s2n-tls to expect either session resumption PSKs or external PSKs. This API should be called prior to selecting a PSK.

**s2n_connection_set_psk_mode** overrides the PSK mode set on the config for this connection.

### Selecting a Pre-Shared Key

By default, the server chooses the first identity in its PSK list that also appears in the client's PSK list. If you would like to implement your own PSK selection logic, use the **s2n_psk_selection_callback** to select the PSK to be used for the connection, along with the following offered PSK APIs to process the client sent list of PSKs.

```c
typedef int (*s2n_psk_selection_callback)(struct s2n_connection *conn, void *context,
                                          struct s2n_offered_psk_list *psk_list);
int s2n_config_set_psk_selection_callback(struct s2n_config *config, s2n_psk_selection_callback cb, void *context);
struct s2n_offered_psk* s2n_offered_psk_new();
int s2n_offered_psk_free(struct s2n_offered_psk **psk);
bool s2n_offered_psk_list_has_next(struct s2n_offered_psk_list *psk_list);
int s2n_offered_psk_list_next(struct s2n_offered_psk_list *psk_list, struct s2n_offered_psk *psk);
int s2n_offered_psk_list_reread(struct s2n_offered_psk_list *psk_list);
int s2n_offered_psk_get_identity(struct s2n_offered_psk *psk, uint8_t** identity, uint16_t *size);
int s2n_offered_psk_list_choose_psk(struct s2n_offered_psk_list *psk_list, struct s2n_offered_psk *psk);
```

**s2n_psk_selection_callback** is a callback function that the server calls to select a PSK from a list of offered PSKs. Implement this callback to use custom PSK selection logic. To examine the list of client PSK identities use the input **psk_list** along with the **s2n_offered_psk_list_next** and **s2n_offered_psk_get_identity** APIs. To choose a client PSK identity, call **s2n_offered_psk_list_choose_psk**. Before a client PSK identity is chosen, the server must have configured its corresponding PSK using **s2n_connection_append_psk**. Currently, this callback is not asynchronous.

**s2n_config_set_psk_selection_callback** sets the **s2n_psk_selection_callback**. If it is not set, the s2n-tls server chooses the first identity in its PSK list that also appears in the client's PSK list.

**s2n_offered_psk_new** creates a new offered PSK object. Pass this object to **s2n_offered_psk_list_next** to retrieve the next PSK from the list.  Use **s2n_offered_psk_list_has_next** prior to this API call to ensure we have not reached the end of the list. **s2n_offered_psk_free** frees the memory associated with the **s2n_offered_psk** object.

**s2n_offered_psk_list_reread** returns the offered PSK list to its original read state. After **s2n_offered_psk_list_reread** is called, the next call to **s2n_offered_psk_list_next** will return the first PSK in the offered PSK list.

**s2n_offered_psk_get_identity** gets the identity and identity length for a given offered PSK object.

**s2n_offered_psk_list_choose_psk** sets the chosen offered PSK to be used for the connection. To disable PSKs for the connection and perform a full handshake instead, set the PSK identity to NULL.

In the following example, **s2n_psk_selection_callback** chooses the first client offered PSK identity present in an external store.

```c
int s2n_psk_selection_callback(struct s2n_connection *conn, void *context,
                               struct s2n_offered_psk_list *psk_list)
{
    struct s2n_offered_psk *offered_psk = s2n_offered_psk_new();

    while (s2n_offered_psk_list_has_next(psk_list)) {
        uint8_t *client_psk_id = NULL;
        uint16_t client_psk_id_len = 0;

        s2n_offered_psk_list_next(psk_list, offered_psk);
        s2n_offered_psk_get_identity(offered_psk, &client_psk_id, &client_psk_id_len);
        struct s2n_psk *psk = user_lookup_identity_db(client_psk_id, client_psk_id_len);

        if (psk) {
            s2n_connection_append_psk(conn, psk);
            s2n_offered_psk_list_choose_psk(psk_list, offered_psk);
            break;
        }
    }
    s2n_offered_psk_free(&offered_psk);
    return S2N_SUCCESS;
}
```

### Retrieve the Negotiated Pre-Shared Key

The following APIs enable the caller to retrieve the PSK selected by the server for the connection.

```c
int s2n_connection_get_negotiated_psk_identity_length(struct s2n_connection *conn, uint16_t *identity_length);
int s2n_connection_get_negotiated_psk_identity(struct s2n_connection *conn, uint8_t *identity, uint16_t max_identity_length);
```

**s2n_connection_get_negotiated_psk_identity** gets the identity of the PSK used to negotiate the connection. **s2n_connection_get_negotiated_psk_identity_length** gets the length of the identity. If the connection performed a full handshake instead of using PSKs then **s2n_connection_get_negotiated_psk_identity_length** returns 0 and **s2n_connection_get_negotiated_psk_identity** does nothing.

## I/O functions

s2n-tls supports both blocking and non-blocking I/O. To use s2n-tls in non-blocking
mode, set the underlying file descriptors as non-blocking (i.e. with
**fcntl**). In blocking mode, each s2n-tls I/O function will not return until it is
complete. In non-blocking mode an s2n-tls I/O function may return while there is
still I/O pending. In this case the value of the **blocked** parameter will be set
to either **S2N_BLOCKED_ON_READ** or **S2N_BLOCKED_ON_WRITE**, depending on the
direction in which s2n-tls is blocked.

s2n-tls I/O functions should be called repeatedly until the **blocked** parameter is
**S2N_NOT_BLOCKED**.

If the read end of the pipe is closed unexpectedly, writing to the pipe will raise
a SIGPIPE signal. **s2n-tls does NOT handle SIGPIPE.** A SIGPIPE signal will cause
the process to terminate unless it is handled or ignored by the application.

### s2n\_negotiate

```c
int s2n_negotiate(struct s2n_connection *conn, s2n_blocked_status *blocked);
```

**s2n_negotiate** performs the initial "handshake" phase of a TLS connection and must be called before any **s2n_recv** or **s2n_send** calls.

### s2n\_send

```c
ssize_t s2n_send(struct s2n_connection *conn
              void *buf,
              ssize_t size,
              s2n_blocked_status *blocked);
```

**s2n_send** writes and encrypts **size** of **buf** data to the associated connection. **s2n_send** will return the number of bytes written, and may indicate a partial write. Partial writes are possible not just for non-blocking I/O, but also for connections aborted while active. **NOTE:** Unlike OpenSSL, repeated calls to **s2n_send** should not duplicate the original parameters, but should update **buf** and **size** per the indication of size written. For example;

```c
s2n_blocked_status blocked;
int written = 0;
char data[10]; /* Some data we want to write */
do {
    int w = s2n_send(conn, data + written, 10 - written, &blocked);
    if (w < 0) {
        /* Some kind of error */
        break;
    }
    written += w;
} while (blocked != S2N_NOT_BLOCKED);
```

### s2n\_sendv\_with\_offset

```c
ssize_t s2n_sendv_with_offset(struct s2n_connection *conn
              const struct iovec *bufs,
              ssize_t count,
              ssize_t offs,
              s2n_blocked_status *blocked);
```

**s2n_sendv_with_offset** works in the same way as **s2n_send** except that it accepts vectorized buffers. **s2n_sendv_with_offset** will return the number of bytes written, and may indicate a partial write. Partial writes are possible not just for non-blocking I/O, but also for connections aborted while active. **NOTE:** Unlike OpenSSL, repeated calls to **s2n_sendv_with_offset** should not duplicate the original parameters, but should update **bufs** and **count** per the indication of size written. For example;

```c
s2n_blocked_status blocked;
int written = 0;
char data[10]; /* Some data we want to write */
struct iovec iov[1];
iov[0].iov_base = data;
iov[0].iov_len = 10;
do {
    int w = s2n_sendv_with_offset(conn, iov, 1, written, &blocked);
    if (w < 0) {
        /* Some kind of error */
        break;
    }
    written += w;
} while (blocked != S2N_NOT_BLOCKED);
```

### s2n\_sendv

```c
ssize_t s2n_sendv(struct s2n_connection *conn
              const struct iovec *bufs,
              ssize_t count,
              s2n_blocked_status *blocked);
```

**s2n_sendv** works in the same way as **s2n_sendv_with_offset** except that the latter's **offs** parameter is implicitly assumed to be 0. Therefore in the partial write case, the caller would have to make sure that **bufs** and **count** fields are modified in a way that takes the partial writes into account.

### s2n\_recv

```c
ssize_t s2n_recv(struct s2n_connection *conn,
             void *buf,
             ssize_t size,
             s2n_blocked_status *blocked);
```

**s2n_recv** decrypts and reads **size* to **buf** data from the associated
connection. **s2n_recv** will return the number of bytes read and also return
"0" on connection shutdown by the peer.

**NOTE:** Unlike OpenSSL, repeated calls to **s2n_recv** should not duplicate the original parameters, but should update **buf** and **size** per the indication of size read. For example;

```c
s2n_blocked_status blocked;
int bytes_read = 0;
char data[10];
do {
    int r = s2n_recv(conn, data + bytes_read, 10 - bytes_read, &blocked);
    if (r < 0) {
        /* Some kind of error */
        break;
    }
    bytes_read += r;
} while (blocked != S2N_NOT_BLOCKED);
```

### s2n\_peek

```c
uint32_t s2n_peek(struct s2n_connection *conn);
```

**s2n_peek** allows users of s2n-tls to peek inside the data buffer of an s2n-tls connection to see if there more data to be read without actually reading it. This is useful when using select() on the underlying s2n-tls file descriptor with a message based application layer protocol. As a single call to s2n_recv may read all data off the underlying file descriptor, select() will be unable to tell you there if there is more application data ready for processing already loaded into the s2n-tls buffer. s2n_peek can then be used to determine if s2n_recv needs to be called before more data comes in on the raw fd.



### s2n\_connection\_set\_send\_cb

```c
int s2n_connection_set_recv_cb(struct s2n_connection *conn, s2n_connection_recv recv);
int s2n_connection_set_send_cb(struct s2n_connection *conn, s2n_connection_send send);
int s2n_connection_set_recv_ctx(struct s2n_connection *conn, void *ctx);
int s2n_connection_set_send_ctx(struct s2n_connection *conn, void *ctx);
```

s2n-tls also provides an I/O abstraction layer in the event the application would
like to keep control over I/O operations. **s2n_connection_set_recv_cb** and
**s2n_connection_set_send_cb** may be used to send or receive data with callbacks
defined by the user. These may be blocking or nonblocking.

```c
typedef int s2n_connection_send(void *io_context, const uint8_t *buf, uint32_t len);
typedef int s2n_connection_recv(void *io_context, uint8_t *buf, uint32_t len);
```

These callbacks take as input a context containing anything needed in the
function (for example, a file descriptor), the buffer holding data to be sent
or received, and the length of the buffer. The **io_context** passed to the
callbacks may be set separately using **s2n_connection_set_recv_ctx** and
**s2n_connection_set_send_ctx**.

The callback may send or receive less than the requested length. The function
should return the number of bytes sent/received, or set errno and return an error code < 0.

### s2n_shutdown

```c
int s2n_shutdown(struct s2n_connection *conn,
                 s2n_blocked_status *blocked);
```

**s2n_shutdown** attempts a closure at the TLS layer. It does not close the underlying transport. The call may block in either direction.
Unlike other TLS implementations, **s2n_shutdown** attempts a graceful shutdown by default. It will not return with success unless a close_notify alert is successfully
sent and received. As a result, **s2n_shutdown** may fail when interacting with a non-conformant TLS implementation.
Once **s2n_shutdown** is complete:
* The s2n_connection handle cannot be used for reading for writing.
* The underlying transport can be closed. Most likely via `close()`.
* The s2n_connection handle can be freed via [s2n_connection_free](#s2n\_connection\_free) or reused via [s2n_connection_wipe](#s2n\_connection\_wipe)

## Using Early Data / 0RTT

TLS1.3 introduced the ability for clients to send data before completing the handshake when using external pre-shared keys or session resumption.

**WARNING:** Early data does not have the same security properties as regular data sent after a successful handshake.
* It is not forward secret. If the PSK or session resumption secret is compromised, then the early data is also compromised.
* It is susceptible to replay attacks unless proper precautions are taken. Early data can be captured and successfully resent by an attacker. See https://tools.ietf.org/rfc/rfc8446#appendix-E.5 for more details, and ["Adding anti-replay protection"](#adding-anti-replay-protection) for how to implement counter measures.

_**Do not enable early data for your application unless you have understood and mitigated the risks.**_

### Configuring session resumption for early data

To use early data with session tickets, early data must be enabled on a server by setting the maximum early data allowed to a non-zero value with **s2n_config_set_server_max_early_data_size** or **s2n_connection_set_server_max_early_data_size**. The server then begins issuing tickets that support early data, and clients can use early data when they use those tickets.

### Configuring external pre-shared keys for early data

To use early data with pre-shared keys, individual pre-shared keys must support early data. In addition to configuring the maximum early data allowed, each pre-shared key needs an associated cipher suite and if applicable, application protocol. The server only accepts early data if the pre-shared key's associated cipher suite and application protocol match the cipher suite and the application protocol negotiated during the handshake.

The maximum early data allowed and cipher suite can be set with **s2n_psk_configure_early_data**. If the connection will negotiate an application protocol then the expected application protocol can be set with **s2n_psk_set_application_protocol**.

### Sending early data

To send early data, your application should call **s2n_send_early_data** before it calls **s2n_negotiate**.

**s2n_connection_get_remaining_early_data_size** can be called to check how much more early data the client is allowed to send. If **s2n_send_early_data** exceeds the allowed maximum, s2n-tls returns a usage error.

Like other IO functions, **s2n_send_early_data** can potentially fail repeatedly with a blocking error before it eventually succeeds: see [I/O Functions](#io-functions) for more information. An application can stop calling **s2n_send_early_data** at any time, even if the function has not returned success yet. If **s2n_send_early_data** does return success, the connection is ready to complete the handshake and begin sending normal data. However, **s2n_send_early_data** can continue to be called to send more early data if desired.

Once a client finishes sending early data, you should call **s2n_negotiate** to complete the handshake just as you would for a handshake that did not include early data.

For example:
```
uint8_t early_data[] = "early data to send";
ssize_t total_data_sent = 0, len = sizeof(early_data);
while (total_data_sent < len) {
    ssize_t data_sent = 0;
    int r = s2n_send_early_data(client_conn, early_data + total_data_sent,
            len - total_data_sent, &data_sent, &blocked);
    total_data_sent += data_sent;
    if (r == S2N_SUCCESS) {
        break;
    } else if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
        exit(1);
    }
}
while (s2n_negotiate(client_conn, &blocked) != S2N_SUCCESS) {
    if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
        exit(1);
    }
}
```

### Receiving early data

To receive early data, your application should call **s2n_recv_early_data** before it calls **s2n_negotiate**.

Like other S2N IO functions, **s2n_recv_early_data** can potentially fail repeatedly with a blocking error before it eventually succeeds: see [I/O Functions](#io-functions) for more information. Once **s2n_recv_early_data** has been called, it must be called until it returns success. If an application stops calling **s2n_recv_early_data** early, some early data may be left unread and cause later calls to **s2n_negotiate** to return fatal errors. Calling **s2n_recv_early_data** again after it returns success is possible but has no effect on the connection.

Once a server has read all early data, you should call **s2n_negotiate** to complete the handshake just as you would for a handshake that did not include early data.

For example:
```
uint8_t early_data[MAX_EARLY_DATA] = { 0 };
ssize_t total_data_recv = 0, data_recv = 0;
while (s2n_recv_early_data(conn, early_data + total_data_recv, MAX_EARLY_DATA - total_data_recv,
        &data_recv, &blocked) != S2N_SUCCESS) {
    total_data_recv += data_recv;
    if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
        exit(1);
    }
}
while (s2n_negotiate(conn, &blocked) != S2N_SUCCESS) {
    if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
        exit(1);
    }
}
```

### Adding anti-replay protection
**s2n-tls does not include anti-replay protection automatically.** Effective anti-replay protection for a multi-server application requires an external state shared by all servers. Without shared state, an attacker can capture early data originally sent to server A and successfully replay it against server B.

The TLS1.3 specification suggests two possible anti-replay solutions that a user can implement:
1. Single-Use Tickets (https://tools.ietf.org/rfc/rfc8446#section-8.1): Valid tickets are stored in a shared database and deleted after use. **s2n_connection_get_negotiated_psk_identity_length** and **s2n_connection_get_negotiated_psk_identity** can be used to get the ticket identifer, or "pre-shared key identity", associated with offered early data.
2. Client Hello Recording (https://tools.ietf.org/rfc/rfc8446#section-8.2): Instead of recording outstanding valid tickets, unique values from recent ClientHellos can be stored. The client hello message can be retrieved with **s2n_connection_get_client_hello** and the pre-shared key identity can be retrieved with **s2n_connection_get_negotiated_psk_identity_length** and **s2n_connection_get_negotiated_psk_identity**, but s2n-tls does not currently provide methods to retrieve the validated binders or the ClientHello.random.

The **s2n_early_data_cb** can be used to hook an anti-replay solution into s2n-tls. The callback can be configured by using **s2n_config_set_early_data_cb**. Using the **s2n_offered_early_data** pointer offered by the callback, **s2n_offered_early_data_reject** or **s2n_offered_early_data_accept** can accept or reject the client request to use early data.

An example implementation:
```
int s2n_early_data_cb_impl(struct s2n_connection *conn, struct s2n_offered_early_data *early_data)
{
    uint16_t identity_size = 0;
    s2n_connection_get_negotiated_psk_identity_length(conn, &identity_size);
    uint8_t *identity = malloc(identity_size);
    s2n_connection_get_negotiated_psk_identity(conn, identity, identity_size);

    if (user_verify_single_use_ticket(identity)) {
        s2n_offered_early_data_accept(early_data);
    } else {
        s2n_offered_early_data_reject(early_data);
    }

    free(identity);
    return S2N_SUCCESS;
}
```

The callback can also be implemented asynchronously by returning **S2N_SUCCESS** without either accepting or rejecting the early data. The handshake will then fail with an **S2N_ERR_T_BLOCKED** error type and **s2n_blocked_status** set to **S2N_BLOCKED_ON_APPLICATION_INPUT** until **s2n_offered_early_data_reject** or **s2n_offered_early_data_accept** is called asynchronously.

An example asynchronous implementation:
```
void *user_accept_or_reject_early_data(void *arg)
{
    struct s2n_offered_early_data *early_data = (struct s2n_offered_early_data *) arg;
    if (user_slowly_verify_early_data(early_data)) {
        s2n_offered_early_data_accept(early_data);
    } else {
        s2n_offered_early_data_reject(early_data);
    }
    return NULL;
}

int s2n_early_data_cb_async_impl(struct s2n_connection *conn, struct s2n_offered_early_data *early_data)
{
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, user_accept_or_reject_early_data, (void *) early_data);
    return S2N_SUCCESS;
}
```

**s2n_offered_early_data_get_context_length** and **s2n_offered_early_data_get_context** can be called to examine the optional user context associated with the early data. Unlike most s2n-tls callbacks, the context is not configured when the callback is set. Instead, the context is associated with the specific pre-shared key or session ticket used for early data. The context can be set for external pre-shared keys by calling **s2n_psk_set_early_data_context**. For session tickets, **s2n_connection_set_server_early_data_context** can be used to set the context the server includes on its new session tickets. Because the server needs to serialize the context when creating a new session ticket, the context is a byte buffer instead of the usual void pointer.


# Examples

To understand the API it may be easiest to see examples in action. s2n-tls's [bin/](https://github.com/aws/s2n-tls/blob/main/bin/) directory
includes an example client (s2nc) and server (s2nd).
