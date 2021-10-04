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

(Optional): Set the CMake variable `CMAKE_INSTALL_PREFIX` to the location libcrypto is installed to. If you do not,
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
find_package(s2n-tls)

....

target_link_libraries(yourExecutableOrLibrary AWS::s2n-tls)
````

And when invoking CMake for your project, do one of two things:
 1. Set the `CMAKE_INSTALL_PREFIX` variable with the path to your s2n-tls build.
 2. If you have globally installed s2n-tls, do nothing, it will automatically be found.

## Building s2n-tls with OpenSSL-1.1.1

To build s2n-tls with OpenSSL-1.1.1, do the following:

```shell
# We keep the build artifacts in the -build directory
cd libcrypto-build

# Download the latest version of OpenSSL
curl -LO https://www.openssl.org/source/openssl-1.1.1-latest.tar.gz
tar -xzvf openssl-1.1.1-latest.tar.gz

# Build openssl libcrypto
cd `tar ztf openssl-1.1.1-latest.tar.gz | head -n1 | cut -f1 -d/`
./config -fPIC no-shared              \
         no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib     \
         no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia\
         no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng                  \
         -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
         --prefix=`pwd`/../../libcrypto-root/
make
make install

# Build s2n-tls
cd ../../
make
```
# Note for 32-bit builds.
The previous instructions work fine with only a few tweaks to your config command. Example:
```shell
setarch i386 ./config -fPIC no-shared     \
        -m32 no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib     \
        no-hw no-mdc2 no-seed no-idea no-camellia\
        no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng     \
        -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS   \
        --prefix=`pwd`/../../libcrypto-root/
```

## Building s2n-tls with OpenSSL-1.0.2

To build s2n-tls with OpenSSL-1.0.2, do the following:

```shell
# We keep the build artifacts in the -build directory
cd libcrypto-build

# Download the latest version of OpenSSL
curl -LO https://www.openssl.org/source/openssl-1.0.2-latest.tar.gz
tar -xzvf openssl-1.0.2-latest.tar.gz

# Build openssl libcrypto
cd `tar ztf openssl-1.0.2-latest.tar.gz | head -n1 | cut -f1 -d/`
./config -fPIC no-shared no-libunbound no-gmp no-jpake no-krb5              \
         no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-store no-zlib     \
         no-hw no-mdc2 no-seed no-idea enable-ec-nistp_64_gcc_128 no-camellia\
         no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng                  \
         -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
         --prefix=`pwd`/../../libcrypto-root/
make depend
make
make install

# Build s2n-tls
cd ../../
make
```

**Mac Users:** please replace "./config" with "./Configure darwin64-x86_64-cc".

## Building s2n-tls with LibreSSL

To build s2n-tls with LibreSSL, do the following:

```shell
# We keep the build artifacts in the -build directory
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
# We keep the build artifacts in the -build directory
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
are in the "s2n.h" header file. Any functions and declarations that are in the "s2n.h" file
are intended to be stable (API and ABI) within major version numbers of s2n-tls releases. Other functions
and structures used in s2n-tls internally can not be considered stable and their parameters, names, and
sizes may change.

The VERSIONING.rst document contains more details about s2n's approach to versions and API changes.

## Preprocessor macros

s2n-tls defines five preprocessor macros that are used to determine what
version of SSL/TLS is in use on a connection.

```c
#define S2N_SSLv2 20
#define S2N_SSLv3 30
#define S2N_TLS10 31
#define S2N_TLS11 32
#define S2N_TLS12 33
#define S2N_TLS13 34
```

These correspond to SSL2.0, SSL3.0, TLS1.0, TLS1.1, TLS1.2 and TLS1.3 respectively.
Note that s2n-tls does not support SSL2.0 for sending and receiving encrypted data,
but does accept SSL2.0 hello messages.

## Enums

s2n-tls defines the following enum types:

### s2n_error_type

```c
typedef enum {
    S2N_ERR_T_OK=0,
    S2N_ERR_T_IO,
    S2N_ERR_T_CLOSED,
    S2N_ERR_T_BLOCKED,
    S2N_ERR_T_ALERT,
    S2N_ERR_T_PROTO,
    S2N_ERR_T_INTERNAL,
    S2N_ERR_T_USAGE
} s2n_error_type;
```

***s2n_error_type*** is used to help applications determine why an s2n-tls function failed.
This enum is optimized for use in C switch statements. Each value in the enum represents
an error "category". See [Error Handling](#error-handling) for more detail.

### s2n_mode

```c
typedef enum {
  S2N_SERVER,
  S2N_CLIENT
} s2n_mode;
```

**s2n_mode** is used to declare connections as server or client type, respectively.

### s2n_blocked_status

```c
typedef enum {
    S2N_NOT_BLOCKED = 0,
    S2N_BLOCKED_ON_READ,
    S2N_BLOCKED_ON_WRITE,
    S2N_BLOCKED_ON_APPLICATION_INPUT,
    S2N_BLOCKED_ON_EARLY_DATA,
} s2n_blocked_status;
```

**s2n_blocked_status** is used in non-blocking mode to indicate in which
direction s2n-tls became blocked on I/O before it returned control to the caller.
This allows an application to avoid retrying s2n-tls operations until I/O is
possible in that direction.

### s2n_blinding

```c
typedef enum { S2N_BUILT_IN_BLINDING, S2N_SELF_SERVICE_BLINDING } s2n_blinding;
```

**s2n_blinding** is used to opt-out of s2n-tls's built-in blinding. Blinding is a
mitigation against timing side-channels which in some cases can leak information
about encrypted data. By default s2n-tls will cause a thread to sleep between 10 and
30 seconds whenever tampering is detected.

Setting the **S2N_SELF_SERVICE_BLINDING** option with **s2n_connection_set_blinding**
turns off this behavior. This is useful for applications that are handling many connections
in a single thread. In that case, if s2n_recv() or s2n_negotiate() return an error,
self-service applications should call **s2n_connection_get_delay** and pause
activity on the connection  for the specified number of nanoseconds before calling
close() or shutdown().

### s2n_status_request_type

```c
typedef enum { S2N_STATUS_REQUEST_NONE, S2N_STATUS_REQUEST_OCSP } s2n_status_request_type;
```

**s2n_status_request_type** is used to define the type, if any, of certificate
status request an S2N_CLIENT should make during the handshake. The only
supported status request type is OCSP, **S2N_STATUS_REQUEST_OCSP**.

### s2n_cert_auth_type

```c
typedef enum { S2N_CERT_AUTH_NONE, S2N_CERT_AUTH_REQUIRED, S2N_CERT_AUTH_OPTIONAL } s2n_cert_auth_type;
```
**s2n_cert_auth_type** is used to declare what type of client certificate authentication to use.
Currently the default for s2n-tls is for neither the server side or the client side to use Client (aka Mutual) authentication.

## Opaque structures

s2n-tls defines several opaque structures that are used for managed objects. Because
these structures are opaque, they can only be safely referenced indirectly through
pointers and their sizes may change with future versions of s2n-tls.

```c
struct s2n_config;
struct s2n_connection;
```

**s2n_config** structures are a configuration object, used by servers for
holding cryptographic certificates, keys and preferences. **s2n_connection**
structures are used to track each connection.


```c
struct s2n_rsa_public_key;
struct s2n_cert_public_key;
```

**s2n_rsa_public_key** and **s2n_cert_public_key** can be used by consumers of s2n-tls to get and set public keys through other API calls.


## Error handling

```
const char *s2n_strerror(int error, const char *lang);
const char *s2n_strerror_debug(int error, const char *lang);
const char *s2n_strerror_name(int error);
````

s2n-tls functions that return 'int' return 0 to indicate success and -1 to indicate
failure. s2n-tls functions that return pointer types return NULL in the case of
failure. When an s2n-tls function returns a failure, s2n_errno will be set to a value
corresponding to the error. This error value can be translated into a string
explaining the error in English by calling s2n_strerror(s2n_errno, "EN").
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

When using s2n-tls outside of `C`, the address of the thread-local `s2n_errno` may be obtained by calling the `int *s2n_errno_location()` function.
This will ensure that the same TLS mechanisms are used with which s2n-tls was compiled.

### Stacktraces
s2n-tls has an mechanism to capture stacktraces when errors occur.
This mechanism is off by default, but can be enabled in code by calling `s2n_stack_traces_enabled_set()`.
It can be enabled globally by setting the environment variable `S2N_PRINT_STACKTRACE=1`.
Note that enabling stacktraces this can significantly slow down unit tests, and can cause failures on unit-tests (such as `s2n_cbc_verify`) that measure the timing of events.

```
bool s2n_stack_traces_enabled();
int s2n_stack_traces_enabled_set(bool newval);

int s2n_calculate_stacktrace(void);
int s2n_print_stacktrace(FILE *fptr);
int s2n_free_stacktrace(void);
int s2n_get_stacktrace(char*** trace, int* trace_size);
```

### Error categories

s2n-tls organizes errors into different "types" to allow applications to do logic on error values without catching all possibilities.
Applications using non-blocking I/O should check error type to determine if the I/O operation failed because it would block or for some other error. To retrieve the type for a given error use `s2n_error_get_type()`.
Applications should perform any error handling logic using these high level types:

```
S2N_ERR_T_OK=0, /* No error */
S2N_ERR_T_IO, /* Underlying I/O operation failed, check system errno */
S2N_ERR_T_CLOSED, /* EOF */
S2N_ERR_T_BLOCKED, /* Underlying I/O operation would block */
S2N_ERR_T_ALERT, /* Incoming Alert */
S2N_ERR_T_PROTO, /* Failure in some part of the TLS protocol. Ex: CBC verification failure */
S2N_ERR_T_INTERNAL, /* Error internal to s2n-tls. A precondition could have failed. */
S2N_ERR_T_USAGE /* User input error. Ex: Providing an invalid cipher preference version */
```

Here's an example that handles errors based on type:

```
s2n_errno = S2N_ERR_T_OK;
if (s2n_recv(conn, &blocked) < 0) {
    switch(s2n_error_get_type(s2n_errno)) {
        case S2N_ERR_T_BLOCKED:
            /* Blocked, come back later */
            return -1;
        case S2N_ERR_T_CLOSED:
            return 0;
        case S2N_ERR_T_IO:
            handle_io_err();
            return -1;
        case S2N_ERR_T_PROTO:
            handle_proto_err();
            return -1;
        case S2N_ERR_T_ALERT:
            log_alert(s2n_connection_get_alert(conn));
            return -1;
        /* Everything else */
        default:
            log_other_error();
            return -1;
    }
}
```


## Initialization and teardown

### s2n\_get\_openssl\_version

```c
unsigned long s2n_get_openssl_version();
```

**s2n_get_openssl_version** returns the version number of OpenSSL that s2n-tls was compiled with. It can be used by
applications to validate at runtime that the versions of s2n-tls and Openssl that they have loaded are correct.


### s2n\_init

```c
int s2n_init();
```

**s2n_init** initializes the s2n-tls library and should be called once in your application,
before any other s2n-tls functions are called. Failure to call s2n_init() will result
in errors from other s2n-tls functions.

### s2n\_crypto\_disable\_init

```c
int s2n_crypto_disable_init();
```

**s2n_crypto_disable_init** prevents s2n-tls from initializing or tearing down the crypto
library. This is most useful when s2n-tls is embedded in an application or environment that
shares usage of the OpenSSL or libcrypto library. Note that if you disable this and are
using a version of OpenSSL/libcrypto < 1.1.x, you will be responsible for library init
and cleanup (specifically OPENSSL_add_all_algorithms() or OPENSSL_crypto_init), and
`EVP_*` APIs will not be usable unless the library is initialized.

This function must be called BEFORE `s2n_init()` to have any effect. It will return an error
if s2n is already initialized.

### s2n\_disable\_atexit

```c
int s2n_disable_atexit();
```

**s2n_disable_atexit** prevents s2n-tls from installing an atexit() handler to clean itself
up. This is most useful when s2n-tls is embedded in an application or environment that
shares usage of the OpenSSL or libcrypto library. Note that this will cause `s2n_cleanup` to
do complete cleanup of s2n-tls when called from the main thread (the thread `s2n_init` was
called from).

This function must be called BEFORE `s2n_init()` to have any effect. It will return an error
if s2n is already initialized.

### s2n\_cleanup

```c
int s2n_cleanup();
```

**s2n_cleanup** cleans up any internal resources used by s2n-tls. This function should be
called from each thread or process that is created subsequent to calling **s2n_init**
when that thread or process is done calling other s2n-tls functions.

## Configuration-oriented functions

### s2n\_config\_new

```c
struct s2n_config * s2n_config_new();
```

**s2n_config_new** returns a new configuration object suitable for associating certs and keys.
This object can (and should) be associated with many connection objects.

### s2n\_config\_free

```c
int s2n_config_free(struct s2n_config *config);
```

**s2n_config_free** frees the memory associated with an **s2n_config** object.

### s2n\_config\_set\_cipher\_preferences

```c
int s2n_config_set_cipher_preferences(struct s2n_config *config,
                                      const char *version);
```

**s2n_config_set_cipher_preferences** sets the security policy that includes the cipher/kem/signature/ecc preferences and protocol version.

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

The "default" and "default_tls13" version is special in that it will be updated with future s2n-tls changes and ciphersuites and protocol versions may be added and removed, or their internal order of preference might change. Numbered versions are fixed and will never change.

"20160411" follows the same general preference order as "default". The main difference is it has a CBC cipher suite at the top. This is to accommodate certain Java clients that have poor GCM implementations. Users of s2n-tls who have found GCM to be hurting performance for their clients should consider this version.

"20170405" is a FIPS compliant cipher suite preference list based on approved algorithms in the [FIPS 140-2 Annex A](http://csrc.nist.gov/publications/fips/fips140-2/fips1402annexa.pdf). Similarly to "20160411", this preference list has CBC cipher suites at the top to accommodate certain Java clients. Users of s2n-tls who plan to enable FIPS mode should consider this version.

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

### s2n\_config\_add\_cert\_chain\_and\_key

```c
int s2n_config_add_cert_chain_and_key(struct s2n_config *config,
                                      const char *cert_chain_pem,
                                      const char *private_key_pem);
```

**s2n_config_add_cert_chain_and_key** associates a certificate chain and a
private key, with an **s2n_config** object. At present, only one
certificate-chain/key pair may be associated with a config.

**cert_chain_pem** should be a PEM encoded certificate chain, with the first
certificate in the chain being your servers certificate. **private_key_pem**
should be a PEM encoded private key corresponding to the server certificate.

### s2n\_config\_add\_cert\_chain\_and\_key\_to\_store

```c
int s2n_config_add_cert_chain_and_key_to_store(struct s2n_config *config,
                                               struct s2n_cert_chain_and_key *cert_key_pair);
```

**s2n_config_add_cert_chain_and_key_to_store** is the preferred method of associating a certificate chain and private key pair with an **s2n_config** object. It is not recommended to free or modify the **cert_key_pair** as any subsequent changes will be reflected in the config.

**s2n_config_add_cert_chain_and_key_to_store** may be called multiple times to support multiple key types(RSA, ECDSA) and multiple domains. On the server side, the certificate selected will be based on the incoming SNI value and the client's capabilities(supported ciphers). In the case of no certificate matching the client's SNI extension or if no SNI extension was sent by the client, the certificate from the **first** call to **s2n_config_add_cert_chain_and_key_to_store** will be selected.

### s2n\_config\_set\_cert\_chain\_and\_key\_defaults

```c
int s2n_config_set_cert_chain_and_key_defaults(struct s2n_config *config,
                                               struct s2n_cert_chain_and_key **cert_key_pairs,
                                               uint32_t num_cert_key_pairs);
```

**s2n_config_set_cert_chain_and_key_defaults** explicitly sets certificate chain and private key pairs to be used as defaults for each auth method (key type). A "default" certificate is used when there is not an SNI match with any other configured certificate. Only one certificate can be set as the default per auth method (one RSA default, one ECDSA default, etc.). All previous default certificates will be cleared and re-set when this API is called. This API is called for a specific **s2n_config** object.

s2n-tls will attempt to automatically choose default certificates for each auth method (key type) based on the order that **s2n_cert_chain_and_key** are added to the **s2n_config** using one of the APIs listed above. **s2n_config_set_cert_chain_and_key_defaults** can be called at any time; s2n-tls will clear defaults and no longer attempt to automatically choose any default certificates.

### s2n\_cert\_tiebreak\_callback
```c
typedef struct s2n_cert_chain_and_key* (*s2n_cert_tiebreak_callback) (struct s2n_cert_chain_and_key *cert1, struct s2n_cert_chain_and_key *cert2, uint8_t *name, uint32_t name_len);
```

**s2n_cert_tiebreak_callback** is invoked if s2n-tls cannot resolve a conflict between two certificates with the same domain name. This function is invoked while certificates are added to an **s2n_config**.
Currently, the only builtin resolution for domain name conflicts is certificate type(RSA, ECDSA, etc).
The callback should return a pointer to the **s2n_cert_chain_and_key** that should be used for dns name **name**. If NULL is returned, the first certificate will be used.
Typically an application will use properties like trust and expiry to implement tiebreaking.

### s2n\_config\_set\_cert\_tiebreak\_callback
```c
int s2n_config_set_cert_tiebreak_callback(struct s2n_config *config, s2n_cert_tiebreak_callback tiebreak_fn);
```

**s2n_config_set_cert_tiebreak_callback** sets the **s2n_cert_tiebreak_callback** for resolving domain name conflicts. If no callback is set, the first certificate added for a domain name will always be preferred.

### s2n\_config\_add\_dhparams

```c
int s2n_config_add_dhparams(struct s2n_config *config,
                            char *dhparams_pem);
```

**s2n_config_add_dhparams** associates a set of Diffie-Hellman parameters with
an **s2n_config** object. **dhparams_pem** should be PEM encoded DH parameters.

### s2n\_config\_set\_protocol\_preferences

```c
int s2n_config_set_protocol_preferences(struct s2n_config *config,
                                        const char **protocols,
                                        int protocol_count);
```

**s2n_config_set_protocol_preferences** sets the application protocol
preferences on an **s2n_config** object.  **protocols** is a list in order of
preference, with most preferred protocol first, and of length
**protocol_count**.  When acting as an **S2N_CLIENT** the protocol list is
included in the Client Hello message as the ALPN extension.  As an
**S2N_SERVER**, the list is used to negotiate a mutual application protocol
with the client. After the negotiation for the connection has completed, the
agreed upon protocol can be retrieved with [s2n_get_application_protocol](#s2n_get_application_protocol)

### s2n\_config\_set\_status\_request\_type

```c
int s2n_config_set_status_request_type(struct s2n_config *config, s2n_status_request_type type);
```

**s2n_config_set_status_request_type** Sets up an S2N_CLIENT to request the
server certificate status during an SSL handshake.  If set to
S2N_STATUS_REQUEST_NONE, no status request is made.

### s2n\_config\_set\_extension\_data

```c
int s2n_config_set_extension_data(struct s2n_config *config, s2n_tls_extension_type type, const uint8_t *data, uint32_t length);
```

**s2n_config_set_extension_data** Sets the extension data in the **s2n_config**
object for the specified extension.  This method will clear any existing data
that is set.   If the data and length parameters are set to NULL, no new data
is set in the **s2n_config** object, effectively clearing existing data.

`s2n_tls_extension_type` is defined as:

```c
    typedef enum {
      S2N_EXTENSION_SERVER_NAME = 0,
      S2N_EXTENSION_MAX_FRAG_LEN = 1,
      S2N_EXTENSION_OCSP_STAPLING = 5,
      S2N_EXTENSION_SUPPORTED_GROUPS = 10,
      S2N_EXTENSION_EC_POINT_FORMATS = 11,
      S2N_EXTENSION_SIGNATURE_ALGORITHMS = 13,
      S2N_EXTENSION_ALPN = 16,
      S2N_EXTENSION_CERTIFICATE_TRANSPARENCY = 18,
      S2N_EXTENSION_RENEGOTIATION_INFO = 65281,
    } s2n_tls_extension_type;
```

At this time the following extensions are supported:

`S2N_EXTENSION_OCSP_STAPLING` - If a client requests the OCSP status of the server
certificate, this is the response used in the CertificateStatus handshake
message.

`S2N_EXTENSION_CERTIFICATE_TRANSPARENCY` - If a client supports receiving SCTs
via the TLS extension (section 3.3.1 of RFC6962) this data is returned within
the extension response during the handshake.  The format of this data is the
SignedCertificateTimestampList structure defined in that document.  See
http://www.certificate-transparency.org/ for more information about Certificate
Transparency.

### s2n\_config\_set\_wall\_clock

```c
int s2n_config_set_wall_clock(struct s2n_config *config, s2n_clock_time_nanoseconds clock_fn, void *data);
```

**s2n_config_set_wall_clock** allows the caller to set a
callback function that will be used to get the system time. The callback function
takes two arguments; a pointer to arbitrary data for use within the callback,
and a pointer to a 64 bit unsigned integer. The first pointer will be set to
the value of **data** which supplied by the caller when setting the callback.
The integer pointed to by the second pointer should be set to the number of
nanoseconds since the Unix epoch (Midnight, January 1st, 1970). The function
should return 0 on success and -1 on error. The default implementation, which uses the REALTIME clock,
will be used if this callback is not manually set.

### s2n\_config\_set\_monotonic\_clock

```c
int s2n_config_set_monotonic_clock(struct s2n_config *config, s2n_clock_time_nanoseconds clock_fn, void *data);
```

**s2n_config_set_monotonic_clock** allows the caller to set a
callback function that will be used to get monotonic time. The callback function
takes two arguments; a pointer to arbitrary data for use within the callback,
and a pointer to a 64 bit unsigned integer. The first pointer will be set to
the value of **data** which supplied by the caller when setting the callback.
The integer pointed to by the second pointer should be an always increasing value. The function
should return 0 on success and -1 on error. The default implementation, which uses the MONOTONIC clock,
will be used if this callback is not manually set.

### s2n\_config\_set\_verification\_ca\_location
```c
int s2n_config_set_verification_ca_location(struct s2n_config *config, const char *ca_pem_filename, const char *ca_dir);
```

**s2n_config_set_verification_ca_location** adds to the trust store from a CA file or directory
containing trusted certificates. Note that the trust store will be initialized with the common locations
for the host operating system by default. To completely override those locations, call
[s2n_config_wipe_trust_store](#s2n_config_wipe_trust_store) before calling this function.
Returns 0 on success and -1 on failure.

### s2n\_config\_add\_pem\_to\_trust\_store
```c
int s2n_config_add_pem_to_trust_store(struct s2n_config *config, const char *pem);
```

**s2n_config_add_pem_to_trust_store**  adds a PEM to the trust store. This will allocate memory, and load PEM into the Trust Store.
Note that the trust store will be initialized with the common locations for the host operating system by default.
To completely override those locations, call [s2n_config_wipe_trust_store](#s2n_config_wipe_trust_store)
before calling this function.
This function returns 0 on success and -1 on error.


### s2n\_config\_wipe\_trust\_store
```c
int s2n_config_wipe_trust_store(struct s2n_config *config);
```

***s2n_config_wipe_trust_store*** clears the trust store.
Note that the trust store will be initialized with the common locations for the host operating system by default.
To completely override those locations, call this before functions like
[s2n_config_set_verification_ca_location](#s2n_config_set_verification_ca_location)
or [s2n_config_add_pem_to_trust_store](#s2n_config_add_pem_to_trust_store).
This function returns 0 on success and -1 on error.

### s2n\_verify\_host\_fn
```c
typedef uint8_t (*s2n_verify_host_fn) (const char *host_name, size_t host_name_len, void *ctx);
```

**s2n_verify_host_fn** is invoked (usually multiple times) during X.509 validation for each name encountered in the leaf certificate.
Return 1 to trust that hostname or 0 to not trust the hostname. If this function returns 1, then the certificate is considered trusted and that portion
of the X.509 validation will succeed. If no hostname results in a 1 being returned,
the certificate will be untrusted and the validation will terminate immediately. The default behavior is to reject all host names found in a certificate
if client mode or client authentication is being used..

### s2n\_config\_set\_verify\_host\_callback
```c
int s2n_config_set_verify_host_callback(struct s2n_config *config, s2n_verify_host_fn, void *ctx);
```

**s2n_config_set_verify_host_callback** sets the callback to use for verifying that a hostname from an X.509 certificate
is trusted. By default, no certificate will be trusted. To override this behavior, set this callback.
See [s2n_verify_host_fn](#s2n_verify_host_fn) for details. This configuration will be inherited by default to new instances of **s2n_connection**.
If a separate callback for different connections using the same config is desired, see
[s2n_connection_set_verify_host_callback](#s2n_connection_set_verify_host_callback).

### s2n\_config\_set\_check\_stapled\_ocsp\_response

```c
int s2n_config_set_check_stapled_ocsp_response(struct s2n_config *config, uint8_t check_ocsp);
```

**s2n_config_set_check_stapled_ocsp_response** toggles whether or not to validate stapled OCSP responses. 1 means OCSP responses
will be validated when they are encountered, while 0 means this step will be skipped. The default value is 1 if the underlying
libCrypto implementation supports OCSP.  Returns 0 on success and -1 on failure.

### s2n\_config\_disable\_x509\_verification

```c
int s2n_config_disable_x509_verification(struct s2n_config *config);
```

**s2n_config_disable_x509_verification** turns off all X.509 validation during the negotiation phase of the connection. This should only be used
for testing or debugging purposes.

```c
int s2n_config_set_max_cert_chain_depth(struct s2n_config *config, uint16_t max_depth);
```

**s2n_config_set_max_cert_chain_depth** sets the maximum allowed depth of a cert chain used for X509 validation. The default value is 7. If this limit
is exceeded, validation will fail if s2n_config_disable_x509_verification() has not been called. 0 is an illegal value and will return an error.
1 means only a root certificate will be used.

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

### s2n\_config\_set\_alert\_behavior
```c
int s2n_config_set_alert_behavior(struct s2n_config *config, s2n_alert_behavior alert_behavior);
```
Sets whether or not a connection should terminate on receiving a WARNING alert from its peer. `alert_behavior` can take the following values:
- `S2N_ALERT_FAIL_ON_WARNINGS` - default behavior: s2n-tls will terminate the connection if its peer sends a WARNING alert.
- `S2N_ALERT_IGNORE_WARNINGS` - with the exception of `close_notify` s2n-tls will ignore all WARNING alerts and keep communicating with its peer.

This setting is ignored in TLS1.3. TLS1.3 terminates a connection for all alerts except user_canceled.

### s2n\_config\_set\_async\_pkey\_validation\_mode
```c
int s2n_config_set_async_pkey_validation_mode(struct s2n_config *config, s2n_async_pkey_validation_mode mode);
```
Sets whether or not a connection should enforce strict signature validation during the `s2n_async_pkey_op_apply` call.
`mode` can take the following values:
- `S2N_ASYNC_PKEY_VALIDATION_FAST` - default behavior: s2n-tls will perform only the minimum validation required for safe use of the asyn pkey operation.
- `S2N_ASYNC_PKEY_VALIDATION_STRICT` - in addition to the previous checks, s2n-tls will also ensure that the signature created as a result of the async private key sign operation matches the public key on the connection.

## Certificate-related functions

### s2n\_cert\_chain\_and\_key\_new

```c
struct s2n_cert_chain_and_key *s2n_cert_chain_and_key_new(void);
```
**s2n_cert_chain_and_key_new** returns a new object used to represent a certificate-chain/key pair. This object can be associated with many config objects.

### s2n\_cert\_chain\_and\_key\_free

```c
int s2n_cert_chain_and_key_free(struct s2n_cert_chain_and_key *cert_and_key);
```
**s2n_cert_chain_and_key_free** frees the memory associated with an **s2n_cert_chain_and_key** object.

### s2n\_cert\_chain\_and\_key\_load\_pem

```c
int s2n_cert_chain_and_key_load_pem(struct s2n_cert_chain_and_key *chain_and_key, const char *chain_pem, const char *private_key_pem);
```

**s2n_cert_chain_and_key_load_pem** associates a certificate chain and private key with an **s2n_cert_chain_and_key** object.

**cert_chain_pem** should be a PEM encoded certificate chain, with the first
certificate in the chain being your leaf certificate. **private_key_pem**
should be a PEM encoded private key corresponding to the leaf certificate.

### s2n\_cert\_chain\_and\_key\_load\_pem\_bytes

```c
int s2n_cert_chain_and_key_load_pem_bytes(struct s2n_cert_chain_and_key *chain_and_key, uint8_t *chain_pem, uint32_t chain_pem_len, uint8_t *private_key_pem, uint32_t private_key_pem_len);
```

**s2n_cert_chain_and_key_load_pem_bytes** associates a certificate chain and private key with an **s2n_cert_chain_and_key** object.

**chain_pem** should be a PEM encoded certificate chain, with the first certificate in the chain being your leaf certificate.
**chain_pem_len** is the length of the certificate chain.
**private_key_pem** should be a PEM encoded private key corresponding to the leaf certificate.
**private_key_pem_len** is the length of the private key.

### s2n\_cert\_chain\_and\_key\_load\_public\_pem\_bytes

```c
int s2n_cert_chain_and_key_load_public_pem_bytes(struct s2n_cert_chain_and_key *chain_and_key, uint8_t *chain_pem, uint32_t chain_pem_len);
```

**s2n_cert_chain_and_key_load_public_pem_bytes** associates a public certificate chain with a **s2n_cert_chain_and_key** object. It does NOT set a private key, so the connection will need to be configured to [offload private key operations](#offloading-asynchronous-private-key-operations).

**chain_pem** should be a PEM encoded certificate chain, with the first certificate in the chain being your leaf certificate.
**chain_pem_len** is the length in bytes of the PEM encoded certificate chain.

### s2n\_cert\_chain\_and\_key\_set\_ctx

```c
int s2n_cert_chain_and_key_set_ctx(struct s2n_cert_chain_and_key *chain_and_key, void *ctx);
```

**s2n_cert_chain_and_key_set_ctx** associates an application defined context with a **s2n_cert_chain_and_key** object.
This is useful when multiple s2n_cert_chain_and_key objects are used and the application would like to associate unique data
with each certificate.

### s2n\_cert\_chain\_and\_key\_get\_ctx

```c
int s2n_cert_chain_and_key_get_ctx(struct s2n_cert_chain_and_key *chain_and_key);
```

**s2n_cert_chain_and_key_set_ctx** returns a previously set context pointer or NULL if no context was set.

### s2n\_cert\_chain\_and\_key\_get\_key

```c
extern s2n_cert_private_key *s2n_cert_chain_and_key_get_private_key(struct s2n_cert_chain_and_key *cert_and_key);
```

**s2n_cert_chain_and_key_get_private_key** returns a private key from
**s2n_cert_chain_and_key** object.

## Client Auth Related calls
Client Auth Related API's are not recommended for normal users. Use of these API's is discouraged.

1. Using these API's requires users to: Complete full x509 parsing and hostname validation in the application layer
2. Application knowledge of TLS code points for certificate types
3. Application dependency on libcrypto to give a libcrypto RSA struct back to s2n-tls

### s2n\_config\_set\_client\_auth\_type and s2n\_connection\_set\_client\_auth\_type
```c
int s2n_config_set_client_auth_type(struct s2n_config *config, s2n_cert_auth_type cert_auth_type);
int s2n_connection_set_client_auth_type(struct s2n_connection *conn, s2n_cert_auth_type cert_auth_type);
```
Sets whether or not a Client Certificate should be required to complete the TLS Connection. If this is set to
**S2N_CERT_AUTH_OPTIONAL** the server will request a client certificate but allow the client to not provide one.
Rejecting a client certificate when using **S2N_CERT_AUTH_OPTIONAL** will terminate the handshake.

### Public Key API's
```c
int s2n_rsa_public_key_set_from_openssl(struct s2n_rsa_public_key *s2n_rsa, RSA *openssl_rsa);
int s2n_cert_public_key_set_cert_type(struct s2n_cert_public_key *cert_pub_key, s2n_cert_type cert_type);
int s2n_cert_public_key_get_rsa(struct s2n_cert_public_key *cert_pub_key, struct s2n_rsa_public_key **rsa);
int s2n_cert_public_key_set_rsa(struct s2n_cert_public_key *cert_pub_key, struct s2n_rsa_public_key rsa);
```
**s2n_rsa_public_key** and **s2n_cert_public_key** are opaque structs. These API's are intended to be used by Implementations of **verify_cert_trust_chain_fn** to
set the public keys found in the Certificate into **public_key_out**.

## Session Caching related calls

s2n-tls includes support for resuming from cached SSL/TLS session, provided
the caller sets (and implements) three callback functions.

### s2n\_config\_set\_cache\_store\_callback

```c
int s2n_config_set_cache_store_callback(struct s2n_config *config, int
        (*cache_store_callback)(struct s2n_connection *conn, void *, uint64_t ttl_in_seconds, const void *key, uint64_t key_size, const void *value, uint64_t value_size), void *data);
```

**s2n_config_set_cache_store_callback** allows the caller to set a callback
function that will be used to store SSL session data in a cache. The callback
function takes seven arguments: a pointer to the s2n_connection object,
a pointer to abitrary data for use within the callback, a 64-bit unsigned integer
specifying the number of seconds the session data may be stored for, a pointer
to a key which can be used to retrieve the cached entry, a 64 bit unsigned
integer specifying the size of this key, a pointer to a value which should be stored,
and a 64 bit unsigned integer specified the size of this value.

### s2n\_config\_set\_cache\_retrieve\_callback

```c
int s2n_config_set_cache_retrieve_callback(struct s2n_config *config, int
        (*cache_retrieve_callback)(struct s2n_connection *conn, void *, const void *key, uint64_t key_size, void *value, uint64_t *value_size), void *data)
```

**s2n_config_set_cache_retrieve_callback** allows the caller to set a callback
function that will be used to retrieve SSL session data from a cache. The
callback function takes six arguments: a pointer to the s2n_connection object,
a pointer to abitrary data for use within the callback, a pointer to a key which
can be used to retrieve the cached entry, a 64 bit unsigned integer specifying
the size of this key, a pointer to a memory location where the value should be stored,
and a pointer to a 64 bit unsigned integer specifing the size of this value.
Initially *value_size will be set to the amount of space allocated for
the value, the callback should set *value_size to the actual size of the
data returned. If there is insufficient space, -1 should be returned.

If the cache is not ready to provide data for the request, S2N_CALLBACK_BLOCKED should be returned.
This will cause s2n_negotiate() to return S2N_BLOCKED_ON_APPLICATION_INPUT.

### s2n\_config\_set\_cache\_delete\_callback

```c
int s2n_config_set_cache_delete_callback(struct s2n_config *config, int
        (*cache_delete_callback))(struct s2n_connection *conn, void *, const void *key, uint64_t key_size), void *data);
```

**s2n_config_set_cache_delete_callback** allows the caller to set a callback
function that will be used to delete SSL session data from a cache. The
callback function takes four arguments: a pointer to s2n_connection object,
a pointer to abitrary data for use within the callback, a pointer to a key
which can be used to delete the cached entry, and a 64 bit unsigned integer
specifying the size of this key.

### s2n\_config\_send\_max\_fragment\_length

```c
int s2n_config_send_max_fragment_length(struct s2n_config *config, uint8_t mfl_code);
```

**s2n_config_send_max_fragment_length** allows the caller to set a TLS Maximum
Fragment Length extension that will be used to fragment outgoing messages.
s2n-tls currently does not reject fragments larger than the configured maximum when
in server mode. The TLS negotiated maximum fragment length overrides the preference set
by the **s2n_connection_prefer_throughput** and **s2n_connection_prefer_low_latency**.

### s2n\_config\_accept\_max\_fragment\_length

```c
int s2n_config_accept_max_fragment_length(struct s2n_config *config);
```

**s2n_config_accept_max_fragment_length** allows the server to opt-in to accept
client's TLS maximum fragment length extension requests.
If this API is not called, and client requests the extension, server will ignore the
request and continue TLS handshake with default maximum fragment length of 8k bytes
## Connection-oriented functions

### s2n\_connection\_new

```c
struct s2n_connection * s2n_connection_new(s2n_mode mode);
```

**s2n_connection_new** creates a new connection object. Each s2n-tls SSL/TLS
connection uses one of these objects. These connection objects can be operated
on by up to two threads at a time, one sender and one receiver, but neither
sending nor receiving are atomic, so if these objects are being called by
multiple sender or receiver threads, you must perform your own locking to
ensure that only one sender or receiver is active at a time. The **mode**
parameters specifies if the caller is a server, or is a client.

Connections objects are re-usable across many connections, and should be
re-used (to avoid deallocating and allocating memory). You should wipe
connections immediately after use.

### s2n\_connection\_set\_config

```c
int s2n_connection_set_config(struct s2n_connection *conn,
                              struct s2n_config *config);
```

**s2n_connection_set_config** Associates a configuration object with a
connection.

### s2n\_connection\_set\_ctx

```c
int s2n_connection_set_ctx(struct s2n_connection *conn, void *ctx);
```

**s2n_connection_set_ctx** sets user defined context in **s2n_connection**
object.

### s2n\_connection\_get\_ctx

```c
void *s2n_connection_get_ctx(struct s2n_connection *conn);
```

**s2n_connection_get_ctx** gets user defined context from **s2n_connection**
object.

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

### s2n\_connection\_is\_valid\_for\_cipher\_preferences

```c
int s2n_connection_is_valid_for_cipher_preferences(struct s2n_connection *conn, const char *version);
```

**s2n_connection_is_valid_for_cipher_preferences** checks if the cipher used by current connection
is supported by a given cipher preferences. It returns
-  1 if the connection satisfies the cipher suite
-  0 if it does not
- -1 on any other errors


### s2n\_connection\_set\_cipher\_preferences

```c
int s2n_connection_set_cipher_preferences(struct s2n_connection *conn, const char *version);
```

**s2n_connection_set_cipher_preferences** sets the cipher preference override for the
s2n_connection. Calling this function is not necessary unless you want to set the
cipher preferences on the connection to something different than what is in the s2n_config.


### s2n\_connection\_set\_protocol\_preferences

```c
int s2n_connection_set_protocol_preferences(struct s2n_connection *conn, const char * const *protocols, int protocol_count);
```

**s2n_connection_set_protocol_preferences** sets the protocol preference override for the
s2n_connection. Calling this function is not necessary unless you want to set the
protocol preferences on the connection to something different than what is in the s2n_config.

### s2n\_set\_server\_name

```c
int s2n_set_server_name(struct s2n_connection *conn,
                        const char *server_name);
```

**s2n_set_server_name** Sets the server name for the connection. In future,
this can be used by clients who wish to use the TLS "Server Name indicator"
extension. At present, client functionality is disabled.

### s2n\_get\_server\_name

```c
const char *s2n_get_server_name(struct s2n_connection *conn);
```

**s2n_get_server_name** returns the server name associated with a connection,
or NULL if none is found. This can be used by a server to determine which server
name the client is using. This function returns the first ServerName entry in the ServerNameList
sent by the client. Subsequent entries are not returned.

### s2n\_connection\_set\_blinding

```c
int s2n_connection_set_blinding(struct s2n_connection *conn, s2n_blinding blinding);
```

**s2n_connection_set_blinding** can be used to configure s2n-tls to either use
built-in blinding (set blinding to S2N_BUILT_IN_BLINDING) or self-service blinding
(set blinding to S2N_SELF_SERVICE_BLINDING).

### s2n\_connection\_get\_delay

```c
uint64_t s2n_connection_get_delay(struct s2n_connection *conn);
```

**s2n_connection_get_delay** returns the number of nanoseconds an application
using self-service blinding should pause before calling close() or shutdown().

### s2n\_connection\_prefer\_throughput(struct s2n_connection *conn)

```c
int s2n_connection_prefer_throughput(struct s2n_connection *conn);
int s2n_connection_prefer_low_latency(struct s2n_connection *conn);
int s2n_connection_set_dynamic_record_threshold(struct s2n_connection *conn, uint32_t resize_threshold, uint16_t timeout_threshold);
```

**s2n_connection_prefer_throughput** and **s2n_connection_prefer_low_latency**
change the behavior of s2n-tls when sending data to prefer either throughput
or low latency. Connections preferring low latency will be encrypted using small
record sizes that can be decrypted sooner by the recipient. Connections
preferring throughput will use large record sizes that minimize overhead.

-Connections default to an 8k outgoing maximum

**s2n_connection_set_dynamic_record_threshold**
provides a smooth transition from **s2n_connection_prefer_low_latency** to **s2n_connection_prefer_throughput**.
**s2n_send** uses small TLS records that fit into a single TCP segment for the resize_threshold bytes (cap to 8M) of data
and reset record size back to a single segment after timeout_threshold seconds of inactivity.

### s2n\_connection\_get\_wire\_bytes

```c
uint64_t s2n_connection_get_wire_bytes_in(struct s2n_connection *conn);
uint64_t s2n_connection_get_wire_bytes_out(struct s2n_connection *conn);
```

**s2n_connection_get_wire_bytes_in** and **s2n_connection_get_wire_bytes_out**
return the number of bytes transmitted by s2n-tls "on the wire", in and out
respectively.

### s2n\_connection\_get\_protocol\_version

```c
int s2n_connection_get_client_hello_version(struct s2n_connection *conn);
int s2n_connection_get_client_protocol_version(struct s2n_connection *conn);
int s2n_connection_get_server_protocol_version(struct s2n_connection *conn);
int s2n_connection_get_actual_protocol_version(struct s2n_connection *conn);
```

**s2n_connection_get_client_protocol_version** returns the protocol version
number supported by the client, **s2n_connection_get_server_protocol_version**
returns the protocol version number supported by the server and
**s2n_connection_get_actual_protocol_version** returns the protocol version
number actually used by s2n-tls for the connection. **s2n_connection_get_client_hello_version**
returns the protocol version used to send the initial client hello message.

Each version number value corresponds to the macros defined as **S2N_SSLv2**,
**S2N_SSLv3**, **S2N_TLS10**, **S2N_TLS11**, **S2N_TLS12**, and **S2N_TLS13**.

### s2n\_connection\_set\_verify\_host\_callback
```c
int s2n_connection_set_verify_host_callback(struct s2n_connection *config, s2n_verify_host_fn host_fn, void *data);
```
Every connection inherits the value of **s2n_verify_host_fn** from it's instance of **s2n_config**.
Since a configuration can (and should) be used for multiple connections, it may be useful to override
this value on a per connection basis. For example, this may be based on a host header from an http request. In that case,
calling this function will override the value inherited from the configuration.
See [s2n_verify_host_fn](#s2n_verify_host_fn) for details.

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

### s2n\_connection\_client\_cert\_used

```c
int s2n_connection_client_cert_used(struct s2n_connection *conn);
```
**s2n_connection_client_cert_used** returns 1 if the handshake completed and Client Auth was
negotiated during the handshake.

### s2n\_get\_application\_protocol

```c
const char *s2n_get_application_protocol(struct s2n_connection *conn);
```

**s2n_get_application_protocol** returns the negotiated application protocol
for a **s2n_connection**.  In the event of no protocol being negotiated, NULL
is returned.

### s2n\_connection\_get\_ocsp\_response

```c
const uint8_t *s2n_connection_get_ocsp_response(struct s2n_connection *conn, uint32_t *length);
```

**s2n_connection_get_ocsp_response** returns the OCSP response sent by a server
during the handshake.  If no status response is received, NULL is returned.

### s2n\_connection\_is\_ocsp\_stapled

```c
int s2n_connection_is_ocsp_stapled(struct s2n_connection *conn);
```

**s2n_connection_is_ocsp_stapled** returns 1 if OCSP response was sent (if connection is in S2N_SERVER mode) or received (if connection is in S2N_CLIENT mode) during handshake, otherwise it returns 0.

### s2n\_connection\_get\_handshake\_type\_name

```c
const char *s2n_connection_get_handshake_type_name(struct s2n_connection *conn);
```

**s2n_connection_get_handshake_type_name** returns a human-readable handshake type name, e.g. "NEGOTIATED|FULL_HANDSHAKE|PERFECT_FORWARD_SECRECY"

### s2n\_connection\_get\_last\_message\_name

```c
const char *s2n_connection_get_last_message_name(struct s2n_connection *conn);
```

**s2n_connection_get_last_message_name** returns the last message name in TLS state machine, e.g. "SERVER_HELLO", "APPLICATION_DATA".

### s2n\_connection\_get\_alert

```c
int s2n_connection_get_alert(struct s2n_connection *conn);
```

If a connection was shut down by the peer, **s2n_connection_get_alert** returns
the TLS alert code that caused a connection to be shut down. s2n-tls considers all
TLS alerts fatal and shuts down a connection whenever one is received.

### s2n\_connection\_get\_cipher

```c
const char * s2n_connection_get_cipher(struct s2n_connection *conn);
```

**s2n_connection_get_cipher** returns a string indicating the cipher suite
negotiated by s2n-tls for a connection in Openssl format, e.g. "ECDHE-RSA-AES128-GCM-SHA256".

### s2n\_connection\_get\_curve

```c
const char * s2n_connection_get_curve(struct s2n_connection *conn);
```

**s2n_connection_get_curve** returns a string indicating the elliptic curve used during ECDHE key exchange. The string "NONE" is returned if no curve was used.

### s2n\_connection\_get\_selected\_cert

```c
struct s2n_cert_chain_and_key s2n_connection_get_selected_cert(struct s2n_connection *conn);
```

Return the certificate that was used during the TLS handshake.

- If **conn** is a server connection, the certificate selected will depend on the
  ServerName sent by the client and supported ciphers.
- If **conn** is a client connection, the certificate sent in response to a CertificateRequest
  message is returned. Currently s2n-tls supports loading only one certificate in client mode. Note that
  not all TLS endpoints will request a certificate.

This function returns NULL if the certificate selection phase of the handshake has not completed
 or if a certificate was not requested by the peer.

### s2n\_cert\_chain\_get\_length

```c
int s2n_cert_chain_get_length(const struct s2n_cert_chain_and_key *chain_and_key, uint32_t *cert_length);
```

**s2n_cert_chain_get_length** gets the length of the certificate chain `chain_and_key`. If the certificate chain `chain_and_key` is NULL an error is thrown.

### s2n\_cert\_chain\_get\_cert

```c
int s2n_cert_chain_get_cert(const struct s2n_cert_chain_and_key *chain_and_key, struct s2n_cert **out_cert, const uint32_t cert_idx);
```

**s2n_cert_chain_get_cert** gets the certificate `out_cert` present at the index `cert_idx` of the certificate chain `chain_and_key`.  If the certificate chain `chain_and_key` is NULL or the certificate index value is not in the acceptable range for the input certificate chain, an error is thrown. Note that the index of the head_cert is zero.

### s2n\_cert\_get\_der

```c
int s2n_cert_get_der(const struct s2n_cert *cert, const uint8_t **out_cert_der, uint32_t *cert_length);
```

**s2n_cert_get_der** gets the certificate `cert` in .der format which is returned in the buffer `out_cert_der`, `cert_len` represents the length of the certificate.

### s2n\_connection\_get_peer\_cert\_chain

```c
int s2n_connection_get_peer_cert_chain(const struct s2n_connection *conn, struct s2n_cert_chain_and_key *s2n_cert_chain_and_key);
```

**s2n_connection_get_peer_cert_chain** gets the validated peer certificate chain from the s2n connection object.

### s2n\_cert\_get\_x509\_extension\_value\_length

```c
int s2n_cert_get_x509_extension_value_length(struct s2n_cert *cert, const uint8_t *oid, uint32_t ext_value_len);
```

**s2n_cert_get_x509_extension_value_length** gets the length of the DER encoding of an ASN.1 X.509 certificate extension value.


### s2n\_cert\_get\_x509\_extension\_value

```c
int s2n_cert_get_x509_extension_value(struct s2n_cert *cert, const uint8_t *oid, uint8_t *ext_value, uint32_t *ext_value_len, bool *critical);
```

**s2n_cert_get_x509_extension_value** gets the DER encoding of an ASN.1 X.509 certificate extension value, it's length and a boolean critical.


### s2n\_cert\_get\_utf8\_string\_from\_extension\_data\_length

```c
int s2n_cert_get_utf8_string_from_extension_data_length(const uint8_t *extension_data, uint32_t extension_len, uint32_t *utf8_str_len);
```

**s2n_cert_get_utf8_string_from_extension_data** gets the UTF8 String length of the ASN.1 X.509 certificate extension data.

### s2n\_cert\_get\_utf8\_string\_from\_extension\_data

```c
int s2n_cert_get_utf8_string_from_extension_data(const uint8_t *extension_data, uint32_t extension_len, uint8_t *out_data, uint32_t *out_len);
```

**s2n_cert_get_utf8_string_from_extension_data** gets the UTF8 String representation of the DER encoded ASN.1 X.509 certificate extension data.

### Session Resumption Related calls

```c
int s2n_config_set_session_state_lifetime(struct s2n_config *config, uint32_t lifetime_in_secs);

int s2n_connection_set_session(struct s2n_connection *conn, const uint8_t *session, size_t length);
int s2n_connection_get_session(struct s2n_connection *conn, uint8_t *session, size_t max_length);
int s2n_connection_get_session_ticket_lifetime_hint(struct s2n_connection *conn);
int s2n_connection_get_session_length(struct s2n_connection *conn);
int s2n_connection_get_session_id_length(struct s2n_connection *conn);
int s2n_connection_get_session_id(struct s2n_connection *conn, uint8_t *session_id, size_t max_length);
int s2n_connection_is_session_resumed(struct s2n_connection *conn);
```

- **lifetime_in_secs** lifetime of the cached session state required to resume a
handshake.
- **session** session will contain serialized session related information needed to resume handshake either using session id or session ticket.
- **length** length of the serialized session state.
- **max_length** Max number of bytes to copy into the **session** buffer.

**s2n_config_set_session_state_lifetime** sets the lifetime of the cached session state. The default value is 15 hours.

**s2n_connection_set_session** de-serializes the session state and updates the connection accordingly. Note that s2n-tls session tickets are versioned and this function will error if it receives a ticket version it doesn't understand. Therefore users need to handle errors for this function in case the inputted ticket is an unrecognized version, which could occur during a long deployment.

**s2n_connection_get_session** serializes the session state from connection and copies into the **session** buffer and returns the number of copied bytes. The output of this function depends on whether session ids or session tickets are being used for resumption.

If the first byte in **session** is 1, then the next 2 bytes will contain the session ticket length, followed by session ticket and session state. In versions TLS1.3 and greater, (which allows multiple session tickets), the most recent session ticket received will be used. Note that the size of the session tickets varies.

If the first byte in **session** is 0, then the next byte will contain session id length, followed by session id and session state.

**s2n_connection_get_session_ticket_lifetime_hint** returns the session ticket lifetime hint in seconds from the server or -1 when session ticket was not used for resumption.

**s2n_connection_get_session_length** returns number of bytes needed to store serialized session state; it can be used to allocate the **session** buffer.

**s2n_connection_get_session_id_length** returns the latest session id length from the connection. Session id length will be 0 for TLS versions >= TLS1.3 as stateful session resumption has not yet been implemented in TLS1.3.

**s2n_connection_get_session_id** gets the latest session id from the connection, copies it into the **session_id** buffer, and returns the number of copied bytes. The session id may change between s2n receiving the ClientHello and sending the ServerHello, but this function will always describe the latest session id. See **s2n_client_hello_get_session_id** to get the session id as it was sent by the client in the ClientHello message.

**s2n_connection_is_session_resumed** returns 1 if the handshake was abbreviated, otherwise returns 0.

## TLS1.3 Session Resumption Related Calls

Session resumption works differently in versions TLS1.3 and higher. While some of the TLS1.2 session resumption APIs have relevance for TLS1.3 session resumption, you need additional APIs to utilize all the capabilities of TLS1.3 session resumption. Session ticket messages are now sent immediately after the handshake in "post-handshake" messages, although more tickets can be sent and received anytime after the handshake has completed. Additionally, multiple session tickets may be issued for the same connection.

Clients need to call s2n_recv after negotiating to receive session ticket messages, as these could arrive anytime post-handshake.

```c
int s2n_config_set_initial_ticket_count(struct s2n_config *config, uint8_t num);
int s2n_connection_add_new_tickets_to_send(struct s2n_connection *conn, uint8_t num);
int s2n_connection_set_server_keying_material_lifetime(struct s2n_connection *conn, uint32_t lifetime_in_secs);

typedef int (*s2n_session_ticket_fn)(struct s2n_connection *conn, void *ctx, struct s2n_session_ticket *ticket);
int s2n_config_set_session_ticket_cb(struct s2n_config *config, s2n_session_ticket_fn callback, void *ctx);
int s2n_session_ticket_get_data_len(struct s2n_session_ticket *ticket, size_t *data_len);
int s2n_session_ticket_get_data(struct s2n_session_ticket *ticket, size_t max_data_len, uint8_t *data);
int s2n_session_ticket_get_lifetime(struct s2n_session_ticket *ticket, uint32_t *session_lifetime);
```

**s2n_config_set_initial_ticket_count** sets the initial number of session tickets the server will send. The default value is one ticket.

**s2n_connection_add_new_tickets_to_send** increases the number of session tickets to send by **num**. If this function is called after the handshake, a server should call s2n_send to send the additional session tickets, as they do not automatically get sent.

**s2n_connection_set_server_keying_material_lifetime** sets the keying material lifetime for session tickets. Use this to ensure session tickets don't get reissued past the lifetime of the certificate used to authenticate the original full handshake. The default lifetime is one week.

**s2n_session_ticket_fn** is invoked whenever a client receives a session ticket. Use this callback in conjunction with the **s2n_session_ticket** getters to get the serialized ticket data and related information. A **ctx** pointer is provided to let a user pass state to the callback, if needed. Be careful if the implemented callback is expensive or allocates a lot of memory, as the server can send many session tickets.

**s2n_config_set_session_ticket_cb** sets the session ticket callback function to be invoked whenever the client receives
a session ticket from the server.

**s2n_session_ticket_get_data_len** takes a s2n_session_ticket object and retrieves the number of bytes needed to store the session ticket. Use this to allocate enough memory for the session ticket in **s2n_session_ticket_get_data**.

**s2n_session_ticket_get_data** takes a s2n_session_ticket object and copies the serialized session ticket data into the
**data** buffer. For this reason **max_data_len** must be set to the maximum amount of bytes that can be copied into
the **data** buffer.

**s2n_session_ticket_get_lifetime** takes a s2n_session_ticket object and retrieves the lifetime of the ticket in seconds.

### Session Ticket Specific calls

```c
int s2n_config_set_session_tickets_onoff(struct s2n_config *config, uint8_t enabled);
int s2n_config_set_ticket_encrypt_decrypt_key_lifetime(struct s2n_config *config, uint64_t lifetime_in_secs);
int s2n_config_set_ticket_decrypt_key_lifetime(struct s2n_config *config, uint64_t lifetime_in_secs);
int s2n_config_add_ticket_crypto_key(struct s2n_config *config, const uint8_t *name, uint32_t name_len, uint8_t *key, uint32_t key_len, uint64_t intro_time_in_seconds_from_epoch);
```

- **enabled** when set to 0 will disable session resumption using session ticket
- **name** name of the session ticket key that should be randomly generated to avoid collisions
- **name_len** length of session ticket key name
- **key** key used to perform encryption/decryption of session ticket
- **key_len** length of the session ticket key
- **intro_time_in_seconds_from_epoch** time at which the session ticket key is introduced. If this is 0, then intro_time_in_seconds_from_epoch is set to now.

**s2n_config_set_session_tickets_onoff** enables and disables session resumption using session ticket

**s2n_config_set_ticket_encrypt_decrypt_key_lifetime** sets how long a session ticket key will be in a state where it can be used for both encryption and decryption of tickets on the server side. The default value is 2 hours.

**s2n_config_set_ticket_decrypt_key_lifetime** sets how long a session ticket key will be in a state where it can used just for decryption of already assigned tickets on the server side. Once decrypted, the session will resume and the server will issue a new session ticket encrypted using a key in encrypt-decrypt state. The default value is 13 hours.

**s2n_config_add_ticket_crypto_key** adds session ticket key on the server side. It would be ideal to add new keys after every (encrypt_decrypt_key_lifetime_in_nanos/2) nanos because
this will allow for gradual and linear transition of a key from encrypt-decrypt state to decrypt-only state.

### Asynchronous private key operations related calls

When s2n-tls is used in non-blocking mode, this set of functions allows user
to move execution of CPU-heavy private key operations out of the main
event loop, preventing **s2n_negotiate** blocking the loop for a few
milliseconds each time the private key operation needs to be performed.

To enable asynchronous private key operations user needs to provide a
callback function **s2n_async_pkey_fn** to
**s2n_config_set_async_pkey_callback** call. This function will be
executed during **s2n_negotiate** call every time an operation on private
key needs to be performed. The argument **op** represents the operation
to perform. From the callback the user can spawn the thread to perform
**op** through **s2n_async_pkey_op_perform** call and immediately return
**S2N_SUCCESS** from the function without waiting for thread to complete.
The **s2n_negotiate** will return **S2N_FAILURE** with **S2N_ERR_T_BLOCKED**
error type and **s2n_blocked_status** **S2N_BLOCKED_ON_APPLICATION_INPUT**,
and will keep giving the same error until the **op** is performed and
applied to the connection through **s2n_async_pkey_op_apply** call.

Note, it is not safe to call multiple functions on the same **conn** or
**op** objects from 2 different threads at the same time. Doing so will
produce undefined behavior. However it is safe to have a call to
function involving only **conn** at the same time with a call to
function involving only **op**, as those 2 objects are not coupled with
each other. It is also safe to free **conn** or **op** at any moment with
respective function calls, with the only exception that **conn** cannot
be freed inside the **s2n_async_pkey_fn** callback.

```c
typedef int (*s2n_async_pkey_fn)(struct s2n_connection *conn, struct s2n_async_pkey_op *op);
extern int s2n_config_set_async_pkey_callback(struct s2n_config *config, s2n_async_pkey_fn fn);
extern int s2n_async_pkey_op_perform(struct s2n_async_pkey_op *op, s2n_cert_private_key *key);
extern int s2n_async_pkey_op_apply(struct s2n_async_pkey_op *op, struct s2n_connection *conn);
extern int s2n_async_pkey_op_free(struct s2n_async_pkey_op *op);
```

- **op** is an opaque object representing private key operation which
needs to be performed.
- **key** is a private key used for operation, can be extracted from
  **conn** through **s2n_connection_get_selected_cert** and
  **s2n_cert_chain_and_key_get_key** calls.

**s2n_async_pkey_fn** is invoked every time some action involving
private key is required during **s2n_negotiate**. The **conn** provides
a pointer to the connection which triggered the callback, the **op** is
a pointer to an operation to be performed. The callback takes the
ownership of **op** object and is responsible for freeing the memory for
it.

**s2n_config_set_async_pkey_callback** sets up the callback to invoke
for asynchronous private key operations and enables asynchronous mode.

**s2n_async_pkey_op_perform** performs the **op** allowing it to be used
to resume the handshake through **s2n_async_pkey_op_apply** call. This
function can be called only once and any subsequent calls will produce a
failure. It is safe to call from a different thread, as long as no other
thread is operating on **op**.

**s2n_async_pkey_op_apply** applies the performed **op** to **conn**
allowing for the next call to **s2n_negotiate** to proceed through
handshake. The function will fail if it is called from
**s2n_async_pkey_fn** callback, or if **op** was not performed through
**s2n_async_pkey_op_perform** call, or if provided **conn** is different
from the original **conn** which initiated callback for this **op**. The
function will succeed only once and any subsequent call will result in
failure for the same **op**.

**s2n_async_pkey_op_free** frees the memory for **op**. Should eventually
be called for each of the **op** received in **s2n_async_pkey_fn** to
avoid any memory leaks.

### Offloading asynchronous private key operations

The **s2n_async_pkey_op_\*** API can be used to perform a private key operation
outside of the S2N context, without copying the private key into S2N memory.

The application can query the type of private
key operation by calling **s2n_async_pkey_op_get_op_type**. In order to perform
an operation, the application must ask S2N to copy the operation's input into an
application supplied buffer. The appropriate buffer size can be determined by calling
**s2n_async_pkey_op_get_input_size**. Once a buffer of proper size is
allocated, the application can request the input data from the **s2n_async_pkey_op**
by calling **s2n_async_pkey_op_get_input**. After the operation is completed, the
finished output can be copied back to S2N by calling **s2n_async_pkey_op_set_output**.
Once the output is set the asynchronous private key operation can be completed by
following the steps outlined [above](#Asynchronous-private-key-operations-related-calls)
to apply the operation and free the op object.

```c
typedef enum { S2N_ASYNC_DECRYPT, S2N_ASYNC_SIGN } s2n_async_pkey_op_type;

extern int s2n_async_pkey_op_get_op_type(struct s2n_async_pkey_op *op, s2n_async_pkey_op_type *type);
extern int s2n_async_pkey_op_get_input_size(struct s2n_async_pkey_op *op, uint32_t *data_len);
extern int s2n_async_pkey_op_get_input(struct s2n_async_pkey_op *op, uint8_t *data, uint32_t data_len);
extern int s2n_async_pkey_op_set_output(struct s2n_async_pkey_op *op, const uint8_t *data, uint32_t data_len);
```

**s2n_async_pkey_op_type** contains the private key operation types.
**s2n_async_pkey_op_get_op_type** retrieves the operation type of the **op**.
**s2n_async_pkey_op_get_input_size** queries the **op** for the size of the input data.
**s2n_async_pkey_op_get_input** retrieves the input data buffer from the **op**.
The **op** will copy the data into a buffer passed in through the **data** parameter.
This buffer is owned by the application, and it is the responsibility of the
application to free it.
**s2n_async_pkey_op_set_output** copies the input data buffer and uses it
to complete the private key operation. The data buffer is owned by the application.
Once **s2n_async_pkey_op_set_output** has returned, the application is free to
release the data buffer.

### s2n\_connection\_free\_handshake

```c
int s2n_connection_free_handshake(struct s2n_connection *conn);
```

**s2n_connection_free_handshake** wipes and releases buffers and memory
allocated during the TLS handshake.  This function should be called after the
handshake is successfully negotiated and logging or recording of handshake data
is complete.

### s2n\_connection\_release\_buffers

```c
int s2n_connection_release_buffers(struct s2n_connection *conn);
```

**s2n_connection_release_buffers** wipes and free the `in` and `out` buffers
associated with a connection.  This function may be called when a connection is
in keep-alive or idle state to reduce memory overhead of long lived connections.

### s2n\_connection\_wipe

```c
int s2n_connection_wipe(struct s2n_connection *conn);
```

**s2n_connection_wipe** wipes an existing connection and allows it to be reused. It erases all data associated with a connection including
pending reads. This function should be called after all I/O is completed and [s2n_shutdown](#s2n\_shutdown) has been called.
Reusing the same connection handle(s) is more performant than repeatedly calling [s2n_connection_new](#s2n\_connection\_new) and
[s2n_connection_free](#s2n\_connection\_free)

### s2n\_connection\_free

```c
int s2n_connection_free(struct s2n_connection *conn);
```

**s2n_connection_free** frees the memory associated with an s2n_connection
handle. The handle is considered invalid after **s2n_connection_free** is used.
[s2n_connection_wipe](#s2n\_connection\_wipe) does not need to be called prior to this function. **s2n_connection_free** performs its own wipe
of sensitive data.

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

**s2n_send** writes and encrypts **size* of **buf** data to the associated connection. **s2n_send** will return the number of bytes written, and may indicate a partial write. Partial writes are possible not just for non-blocking I/O, but also for connections aborted while active. **NOTE:** Unlike OpenSSL, repeated calls to **s2n_send** should not duplicate the original parameters, but should update **buf** and **size** per the indication of size written. For example;

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


### s2n_mem_set_callbacks

```c
typedef int (*s2n_mem_init_callback)(void);
typedef int (*s2n_mem_cleanup_callback)(void);
typedef int (*s2n_mem_malloc_callback)(void **ptr, uint32_t requested, uint32_t *allocated);
typedef int (*s2n_mem_free_callback)(void *ptr, uint32_t size);

extern int s2n_mem_set_callbacks(s2n_mem_init_callback mem_init_callback, s2n_mem_cleanup_callback mem_cleanup_callback, s2n_mem_malloc_callback mem_malloc_callback, s2n_mem_free_callback mem_free_callback);
```


**s2n_mem_set_callbacks** allows the caller to over-ride s2n-tls's internal memory
handling functions. To work correctly, **s2n_mem_set_callbacks** must be called
before **s2n_init**. **s2n_mem_init_callback** should be a function that will
be called when s2n-tls is initialized.  **s2n_mem_cleanup_callback** will be called
when **s2n_cleanup** is executed. **s2n_mem_malloc_callback** should be a
function that can allocate at least **requested** bytes of memory and store the
location of that memory in **\*ptr**, and the size of the allocated data in
**\*allocated**. The function may choose to allocate more memory than was requested.
s2n-tls will consider all allocated memory available for use, and will attempt to
free all allocated memory when able. **s2n_mem_free_callback** should be a
function that can free memory.


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
