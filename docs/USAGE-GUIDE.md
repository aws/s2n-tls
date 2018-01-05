# Using s2n

s2n is a C library, and is built using Make. To clone the latest
copy of s2n from git use:

```shell
git clone https://github.com/awslabs/s2n.git
cd s2n
```

## Building s2n with existing libcrypto
### make Instructions
To build s2n with an existing libcrypto installation, store its root folder in the
`LIBCRYPTO_ROOT` environment variable.
```shell
# /usr/local/ssl/lib should contain libcrypto.a
LIBCRYPTO_ROOT=/usr/local/ssl make
```
### CMake Instructions

Throughout this document, there are instructions for setting a `LIBCRYPTO_ROOT` environment variable, or setting install prefixes to `s2n/lib-crypto-root`. If you 
are using CMake that step is unnecessary. Just follow the instructions here to use any build of libcrypto.

(Required): You need at least CMake version 3.0 to fully benefit from Modern CMake. See [this](https://www.youtube.com/watch?v=bsXLMQ6WgIk) for more information.

(Optional): Set the CMake variable `LIBCRYPTO_ROOT_DIR` to any libcrypto build on your machine. If you do not,
the default installation on your machine will be used.

(Optional): Set the CMake variable `BUILD_SHARED_LIBS=ON` to build shared libraries. The default is static.
 
We recommend an out-of-source build. Suppose you have a directory `s2n` which contains the s2n source code. At the same level
we can create a directory called `s2n-build`

For example, we can build and install shared libs using ninja as our build system, and the system libcrypto implementation.

````shell
mkdir s2n-build
cd s2n-build
cmake ../s2n -DBUILD_SHARED_LIBS=ON -GNinja
ninja
ninja test 
sudo ninja install
````

For another example, we can prepare an Xcode project using static libs using a libcrypto implementation in the directory `$HOME/s2n-user/builds/libcrypto-impl`.

````shell
mkdir s2n-build
cd s2n-build
cmake ../s2n -DLIBCRYPTO_ROOT_DIR=$HOME/s2n-user/builds/libcrypto-impl -G "Xcode"
# now open the project in Xcode and build from there, or use the Xcode CLI
````

Or, for unix style vanilla builds:

````shell
mkdir s2n-build
cd s2n-build
cmake ../s2n
make
make test
sudo make install
````

### Consuming s2n via. CMake
s2n ships with modern CMake finder scripts if CMake is used for the build. To take advantage of this from your CMake script, all you need to do to compile and link against s2n in your project is:

````shell
find_package(s2n)

....

target_link_libraries(yourExecutableOrLibrary s2n)
````

And when invoking CMake for your project, do one of three things:
 1. Append the `CMAKE_PREFIX_PATH` variable with the path to your s2n build.
 2. Set the `s2n_DIR` CMake variable
 3. If you have globally installed s2n, do nothing, it will automatically be found.
 
## Building s2n with OpenSSL-1.1.0

To build s2n with OpenSSL-1.1.0, do the following:

```shell
# We keep the build artifacts in the -build directory
cd libcrypto-build

# Download the latest version of OpenSSL
curl -LO https://www.openssl.org/source/openssl-1.1.0-latest.tar.gz
tar -xzvf openssl-1.1.0-latest.tar.gz

# Build openssl libcrypto  (NOTE: check directory name 1.1.0-latest unpacked as)
cd openssl-1.1.0e
./config -fPIC no-shared              \
         no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-zlib     \
         no-hw no-mdc2 no-seed no-idea enable-ec_nistp_64_gcc_128 no-camellia\
         no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng                  \
         -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
         --prefix=`pwd`/../../libcrypto-root/
make
make install

# Build s2n
cd ../../
make
```

## Building s2n with OpenSSL-1.0.2

To build s2n with OpenSSL-1.0.2, do the following:

```shell
# We keep the build artifacts in the -build directory
cd libcrypto-build

# Download the latest version of OpenSSL
curl -LO https://www.openssl.org/source/openssl-1.0.2-latest.tar.gz
tar -xzvf openssl-1.0.2-latest.tar.gz

# Build openssl libcrypto  (NOTE: check directory name 1.0.2-latest unpacked as)
cd openssl-1.0.2k
./config -fPIC no-shared no-libunbound no-gmp no-jpake no-krb5              \
         no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-store no-zlib     \
         no-hw no-mdc2 no-seed no-idea enable-ec-nistp_64_gcc_128 no-camellia\
         no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng                  \
         -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
         --prefix=`pwd`/../../libcrypto-root/
make depend
make
make install

# Build s2n
cd ../../
make
```

**Mac Users:** please replace "./config" with "./Configure darwin64-x86_64-cc".

## Building s2n with LibreSSL

To build s2n with LibreSSL, do the following:

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

# Build s2n
cd ../../
make
```

once built, static and dynamic libraries for s2n will be available in the lib/
directory.

## Building s2n with BoringSSL

To build s2n with BoringSSL, you must check out a copy of the BoringSSL
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

# Build s2n
cd ../../../
make
```

once built, static and dynamic libraries for s2n will be available in the lib/
directory.

## mlock() and system limits 

Internally s2n uses mlock() to prevent memory from being swapped to disk. The
s2n build tests may fail in some environments where the default limit on locked
memory is too low. To check this limit, run:

```shell
ulimit -l
```

to raise the limit, consult the documentation for your platform.

### Disabling mlock()
To disable s2n's mlock behavior, run your application with the `S2N_DONT_MLOCK` environment variable set. 
s2n also reads this for unit tests. Try `S2N_DONT_MLOCK=1 make` if you're having mlock failures during unit tests.

## client mode

At this time s2n does not perform certificate validation and client mode is
disabled as a precaution. To enable client mode for testing and development,
set the **S2N_ENABLE_CLIENT_MODE** environment variable.

```shell
export S2N_ENABLE_CLIENT_MODE=1
```

# s2n API

The API exposed by s2n is the set of functions and declarations that
are in the "s2n.h" header file. Any functions and declarations that are in the "s2n.h" file
are intended to be stable (API and ABI) within major version numbers of s2n releases. Other functions 
and structures used in s2n internally can not be considered stable and their parameters, names, and 
sizes may change.

At this time (Summer 2015), there has been no numbered release of s2n and all APIs are subject to change based
on the feedback and preferences of early adopters.

## Preprocessor macros

s2n defines five preprocessor macros that are used to determine what 
version of SSL/TLS is in use on a connection. 

```c
#define S2N_SSLv2 20
#define S2N_SSLv3 30
#define S2N_TLS10 31
#define S2N_TLS11 32
#define S2N_TLS12 33
```

These correspond to SSL2.0, SSL3.0, TLS1.0, TLS1.1 and TLS1.2 respectively.
Note that s2n does not support SSL2.0 for sending and receiving encrypted data,
but does accept SSL2.0 hello messages.

## Enums

s2n defines five enum types:

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

***s2n_error_type*** is used to help applications determine why an s2n function failed.
This enum is optimized for use in C switch statements. Each value in the enum represents
an error "category". See [Error Handling](#error-handling) for more detail.


```c
typedef enum { S2N_SERVER, S2N_CLIENT } s2n_mode;
```

**s2n_mode** is used to declare connections as server or client type,
respectively.  At this time, s2n does not function as a client and only
S2N_SERVER should be used.

```c
typedef enum { S2N_NOT_BLOCKED, S2N_BLOCKED_ON_READ, S2N_BLOCKED_ON_WRITE } s2n_blocked_status;
```

**s2n_blocked_status** is used in non-blocking mode to indicate in which
direction s2n became blocked on I/O before it returned control to the caller.
This allows an application to avoid retrying s2n operations until I/O is 
possible in that direction.

```c
typedef enum { S2N_BUILT_IN_BLINDING, S2N_SELF_SERVICE_BLINDING } s2n_blinding;
```

**s2n_blinding** is used to opt-out of s2n's built-in blinding. Blinding is a
mitigation against timing side-channels which in some cases can leak information
about encrypted data. By default s2n will cause a thread to sleep between 1ms and 
10 seconds whenever tampering is detected. 

Setting the **S2N_SELF_SERVICE_BLINDING** option with **s2n_connection_set_blinding**
turns off this behavior. This is useful for applications that are handling many connections
in a single thread. In that case, if s2n_recv() or s2n_negotiate() return an error, 
self-service applications should call **s2n_connection_get_delay** and pause 
activity on the connection  for the specified number of nanoseconds before calling
close() or shutdown().

```c
typedef enum { S2N_STATUS_REQUEST_NONE, S2N_STATUS_REQUEST_OCSP } s2n_status_request_type;
```

**s2n_status_request_type** is used to define the type, if any, of certificate
status request an S2N_CLIENT should make during the handshake. The only
supported status request type is OCSP, **S2N_STATUS_REQUEST_OCSP**.


```c
typedef enum { S2N_CERT_AUTH_NONE, S2N_CERT_AUTH_REQUIRED, S2N_CERT_AUTH_OPTIONAL } s2n_cert_auth_type;
```
**s2n_cert_auth_type** is used to declare what type of client certificiate authentication to use.
Currently the default for s2n is for neither the server side or the client side to use Client (aka Mutual) authentication.

```c
typedef enum {
    S2N_CERT_TYPE_RSA_SIGN = 1,
    S2N_CERT_TYPE_DSS_SIGN = 2,
    S2N_CERT_TYPE_RSA_FIXED_DH = 3,
    S2N_CERT_TYPE_DSS_FIXED_DH = 4,
    S2N_CERT_TYPE_RSA_EPHEMERAL_DH_RESERVED = 5,
    S2N_CERT_TYPE_DSS_EPHEMERAL_DH_RESERVED = 6,
    S2N_CERT_TYPE_FORTEZZA_DMS_RESERVED = 20,
    S2N_CERT_TYPE_ECDSA_SIGN = 64,
    S2N_CERT_TYPE_RSA_FIXED_ECDH = 65,
    S2N_CERT_TYPE_ECDSA_FIXED_ECDH = 66,
} s2n_cert_type;
```
**s2n_cert_type** is used to define what type of Certificate was used in a connection.

## Opaque structures

s2n defines two opaque structures that are used for managed objects. Because
these structures are opaque, they can only be safely referenced indirectly through
pointers and their sizes may change with future versions of s2n.

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

**s2n_rsa_public_key** and **s2n_cert_public_key** can be used by consumers of s2n to get and set public keys through other API calls.


## Error handling

```
const char *s2n_strerror(int error, const char *lang);
const char *s2n_strerror_debug(int error, const char *lang);
````

s2n functions that return 'int' return 0 to indicate success and -1 to indicate
failure. s2n functions that return pointer types return NULL in the case of
failure. When an s2n function returns a failure, s2n_errno will be set to a value
corresponding to the error. This error value can be translated into a string
explaining the error in English by calling s2n_strerror(s2n_errno, "EN");
A string containing internal debug information, including filename and line number, can be generated with `s2n_strerror_debug`
This string is useful to include when reporting issues to the s2n development team.

Example:

```
if (s2n_config_set_cipher_preferences(config, prefs) < 0) {
    printf("Setting cipher prefs failed! %s : %s", s2n_strerror(s2n_errno, "EN"), s2n_strerror_debug(s2n_errno, "EN"));
    return -1;
}
```

**NOTE**: To avoid possible confusion, s2n_errno should be cleared after processing an error: `s2n_errno = S2N_ERR_T_OK`

### Error categories

s2n organizes errors into different "types" to allow applications to do logic on error values without catching all possibilities. 
Applications using non-blocking I/O should check error type to determine if the I/O operation failed because it would block or for some other error. To retrieve the type for a given error use `s2n_error_get_type()`.
Applications should perform any error handling logic using these high level types:

```
S2N_ERR_T_OK=0, /* No error */
S2N_ERR_T_IO, /* Underlying I/O operation failed, check system errno */
S2N_ERR_T_CLOSED, /* EOF */
S2N_ERR_T_BLOCKED, /* Underlying I/O operation would block */
S2N_ERR_T_ALERT, /* Incoming Alert */
S2N_ERR_T_PROTO, /* Failure in some part of the TLS protocol. Ex: CBC verification failure */
S2N_ERR_T_INTERNAL, /* Error internal to s2n. A precondition could have failed. */
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

### s2n\_init

```c
int s2n_init();
```

**s2n_init** initializes the s2n library and should be called once in your application,
before any other s2n functions are called. Failure to call s2n_init() will result
in errors from other s2n functions.

### s2n\_cleanup

```c
int s2n_cleanup();
```

**s2n_cleanup** cleans up any internal resources used by s2n. This function should be
called from each thread or process that is created subsequent to calling **s2n_init**
when that thread or process is done calling other s2n functions.

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

**s2n_config_set_cipher_preferences** sets the ciphersuite and protocol versions. The currently supported versions are;

|    version | SSLv3 | TLS1.0 | TLS1.1 | TLS1.2 | AES-CBC | ChaCha20-Poly1305 | AES-GCM | 3DES | RC4 | DHE | ECDHE |
|------------|-------|--------|--------|--------|---------|-------------------|---------|------|-----|-----|-------|
| "default"  |       |   X    |    X   |    X   |    X    |         X         |    X    |      |     |     |   X   |
| "20170718" |       |   X    |    X   |    X   |    X    |                   |    X    |      |     |     |   X   |
| "20170405" |       |   X    |    X   |    X   |    X    |                   |    X    |  X   |     |     |   X   |
| "20170328" |       |   X    |    X   |    X   |    X    |                   |    X    |  X   |     |  X  |   X   |
| "20170210" |       |   X    |    X   |    X   |    X    |         X         |    X    |      |     |     |   X   |
| "20160824" |       |   X    |    X   |    X   |    X    |                   |    X    |      |     |     |   X   |
| "20160804" |       |   X    |    X   |    X   |    X    |                   |    X    |  X   |     |     |   X   |
| "20160411" |       |   X    |    X   |    X   |    X    |                   |    X    |  X   |     |     |   X   |
| "20150306" |       |   X    |    X   |    X   |    X    |                   |    X    |  X   |     |     |   X   |
| "20150214" |       |   X    |    X   |    X   |    X    |                   |    X    |  X   |     |  X  |       |
| "20150202" |       |   X    |    X   |    X   |    X    |                   |         |  X   |     |  X  |       |
| "20141001" |       |   X    |    X   |    X   |    X    |                   |         |  X   |  X  |  X  |       |
| "20140601" |   X   |   X    |    X   |    X   |    X    |                   |         |  X   |  X  |  X  |       |

The "default" version is special in that it will be updated with future s2n changes and ciphersuites and protocol versions may be added and removed, or their internal order of preference might change. Numbered versions are fixed and will never change. 

"20160411" follows the same general preference order as "default". The main difference is it has a CBC cipher suite at the top. This is to accomodate certain Java clients that have poor GCM implementations. Users of s2n who have found GCM to be hurting performance for their clients should consider this version.

"20170405" is a FIPS compliant cipher suite preference list based on approved algorithms in the [FIPS 140-2 Annex A](http://csrc.nist.gov/publications/fips/fips140-2/fips1402annexa.pdf). Similarly to "20160411", this perference list has CBC cipher suites at the top to accomodate certain Java clients. Users of s2n who plan to enable FIPS mode should consider this version.

s2n does not expose an API to control the order of preference for each ciphersuite or protocol version. s2n follows the following order:

*NOTE*: All ChaCha20-Poly1305 cipher suites will not be available if s2n is not built with an Openssl 1.1.0 libcrypto. The
underlying encrpyt/decrypt functions are not available in older versions.

1. Always prefer the highest protocol version supported
2. Always use forward secrecy where possible. Prefer ECDHE over DHE. 
3. Prefer encryption ciphers in the following order: AES128, AES256, ChaCha20, 3DES, RC4.
4. Prefer record authentication modes in the following order: GCM, Poly1305, SHA256, SHA1, MD5.

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
      S2N_EXTENSION_OCSP_STAPLING = 5,
      S2N_EXTENSION_CERTIFICATE_TRANSPARENCY = 18
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

### s2n\_config\_set\_nanoseconds\_since\_epoch\_callback

```c
int s2n_config_set_nanoseconds_since_epoch_callback(struct s2n_config *config, int (*nanoseconds_since_epoch)(void *, uint64_t *), void * data);
```

**s2n_config_set_nanoseconds_since_epoch_callback** allows the caller to set a
callback function that will be used to get the time. The callback function
takes two arguments; a pointer to abitrary data for use within the callback,
and a pointer to a 64 bit unsigned integer. The first pointer will be set to
the value of **data** which supplied by the caller when setting the callback.
The integer pointed to by the second pointer should be set to the number of
nanoseconds since the Unix epoch (Midnight, January 1st, 1970). The function
should return 0 on success and -1 on error. The function is also required to 
implement a monotonic time source; the number of nanoseconds returned should
never decrease between calls.

### s2n\_config\_set\_client\_hello\_cb

```c
int s2n_config_set_client_hello_cb(struct s2n_config *config, s2n_client_hello_fn client_hello_callback, void *ctx);
```

**s2n_config_set_client_hello_cb** allows the caller to set a callback function
that will be called after ClientHello was parsed.

```c
typedef int s2n_client_hello_fn(struct s2n_connection *conn, void *ctx);
```

The callback function take as an input s2n connection, which received
ClientHello and context provided in **s2n_config_set_client_hello_cb**. The
callback can get any ClientHello infromation from the connection and use
**s2n_connection_set_config** call to change the config of the connection.

The callback can return 0 to continue handshake in s2n or it can return negative
value to make s2n terminate handshake early with fatal handshake failure alert.

## Client Auth Related calls
Client Auth Related API's are not recommended for normal users. Use of these API's is discouraged.

1. Using these API's requires users to: Complete full x509 parsing and hostname validation in the application layer
2. Application knowledge of TLS code points for certificate types
3. Application dependency on libcrypto to give a libcrypto RSA struct back to s2n

### s2n\_config\_set\_client\_auth\_type and s2n\_connection\_set\_client\_auth\_type
```c
int s2n_config_set_client_auth_type(struct s2n_config *config, s2n_cert_auth_type cert_auth_type);
int s2n_connection_set_client_auth_type(struct s2n_connection *conn, s2n_cert_auth_type cert_auth_type);
```
Sets whether or not a Client Certificate should be required to complete the TLS Connection. If this is set to
**S2N_CERT_AUTH_OPTIONAL** the server will request a client certificate but allow the client to not provide one.
If this is set to **S2N_CERT_AUTH_REQUIRED** or **S2N_CERT_AUTH_OPTIONAL** then a **verify_cert_trust_chain_fn** callback should be provided as well since the current
default is for s2n to accept all RSA Certs on the client side, and deny all certs on the server side. Rejecting a
client certificate when using **S2N_CERT_AUTH_OPTIONAL** will terminate the handshake.


### verify_cert_trust_chain_fn

```c
int verify_cert_trust_chain(struct s2n_connection *conn, uint8_t *der_cert_chain_in, uint32_t cert_chain_len, struct s2n_cert_public_key *public_key_out, void *context);
```
 - **conn** The connection the certificate chain is validated for
 - **der_cert_chain_in** The DER encoded full chain of certificates recieved
 - **cert_chain_len** The length in bytes of the DER encoded Cert Chain
 - **public_key_out** The public key that should be updated with the key extracted from the first certificate in the chain (the leaf Cert)
 - **context** A pointer to any caller defined context data needed for the callback (Cert Trust Store, etc)
 - **return Value** The function should return 0 if the Certificate Chain is trusted and public key extraction was successful, and less than 0 if any Certificate in the chain is untrusted, or there was some other error.

**verify_cert_trust_chain_fn** defines a Callback Function Signature intended to be used only in special circumstances, and may be removed in a later release.
Implementations should Verify the Certificate Chain of trust, and place the leaf Certificate's Public Key in the public_key_out parameter.

### Public Key API's
```c
int s2n_rsa_public_key_set_from_openssl(struct s2n_rsa_public_key *s2n_rsa, RSA *openssl_rsa);
int s2n_cert_public_key_set_cert_type(struct s2n_cert_public_key *cert_pub_key, s2n_cert_type cert_type);
int s2n_cert_public_key_get_rsa(struct s2n_cert_public_key *cert_pub_key, struct s2n_rsa_public_key **rsa);
int s2n_cert_public_key_set_rsa(struct s2n_cert_public_key *cert_pub_key, struct s2n_rsa_public_key rsa);
```
**s2n_rsa_public_key** and **s2n_cert_public_key** are opaque structs. These API's are intended to be used by Implementations of **verify_cert_trust_chain_fn** to
set the public keys found in the Certificate into **public_key_out**.

### s2n_config_set_verify_cert_chain_cb and s2n_connection_set_verify_cert_chain_cb

```c
int s2n_config_set_verify_cert_chain_cb(struct s2n_config *config, verify_cert_trust_chain_fn *callback, void *context);
int s2n_connection_set_verify_cert_chain_cb(struct s2n_connection *conn, verify_cert_trust_chain_fn *callback, void *context);
```

Sets the **verify_cert_trust_chain_fn** callback function and context that will be used when verifying Certificates for the connection.

## Session Caching related calls

s2n includes support for resuming from cached SSL/TLS session, provided 
the caller sets (and implements) three callback functions.

### s2n\_config\_set\_cache\_store\_callback

```c
int s2n_config_set_cache_store_callback(struct s2n_config *config, int (*cache_store)(void *, uint64_t ttl_in_seconds, const void *key, uint64_t key_size, const void *value, uint64_t value_size), void *data);
```

**s2n_config_set_cache_store_callback** allows the caller to set a callback
function that will be used to store SSL session data in a cache. The callback
function takes six arguments: a pointer to abitrary data for use within the
callback, a 64-bit unsigned integer specifying the number of seconds the
session data may be stored for, a pointer to a key which can be used to
retrieve the cached entry, a 64 bit unsigned integer specifying the size of
this key, a pointer to a value which should be stored, and a 64 bit unsigned
integer specified the size of this value.

### s2n\_config\_set\_cache\_retrieve\_callback

```c
int s2n_config_set_cache_retrieve_callback(struct s2n_config *config, int (*cache_retrieve)(void *, const void *key, uint64_t key_size, void *value, uint64_t *value_size), void *data)
```

**s2n_config_set_cache_retrieve_callback** allows the caller to set a callback
function that will be used to retrieve SSL session data from a cache. The
callback function takes five arguments: a pointer to abitrary data for use
within the callback, a pointer to a key which can be used to retrieve the
cached entry, a 64 bit unsigned integer specifying the size of this key, a
pointer to a memory location where the value should be stored,
and a pointer to a 64 bit unsigned integer specifing the size of this value.
Initially *value_size will be set to the amount of space allocated for
the value, the callback should set *value_size to the actual size of the
data returned. If there is insufficient space, -1 should be returned.

### s2n\_config\_set\_cache\_delete\_callback

```c
int s2n_config_set_cache_delete_callback(struct s2n_config *config, int (*cache_delete))(void *, const void *key, uint64_t key_size), void *data);
```

**s2n_config_set_cache_delete_callback** allows the caller to set a callback
function that will be used to delete SSL session data from a cache. The
callback function takes three arguments: a pointer to abitrary data for use
within the callback, a pointer to a key which can be used to delete the
cached entry, and a 64 bit unsigned integer specifying the size of this key.

### s2n\_config\_send\_max\_fragment\_length

```c
int s2n_config_send_max_fragment_length(struct s2n_config *config, uint8_t mfl_code);
```

**s2n_config_send_max_fragment_length** allows the caller to set a TLS Maximum
Fragment Length extension that will be used to fragment outgoing messages.
s2n currently does not reject fragments larger than the configured maximum when
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

**s2n_connection_new** creates a new connection object. Each s2n SSL/TLS
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

**s2n_connection_set_fd** sets the file-descriptor for an s2n connection. This
file-descriptor should be active and connected. s2n also supports setting the
read and write file-descriptors to different values (for pipes or other unusual
types of I/O).

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
name the client is using.

### s2n\_connection\_set\_blinding

```c
int s2n_connection_set_blinding(struct s2n_connection *conn, s2n_blinding blinding);
```

**s2n_connection_set_blinding** can be used to configure s2n to either use
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
```

**s2n_connection_prefer_throughput** and **s2n_connection_prefer_low_latency**
change the behavior of s2n when sending data to prefer either throughput
or low latency. Connections prefering low latency will be encrypted using small
record sizes that can be decrypted sooner by the recipient. Connections
prefering throughput will use large record sizes that minimize overhead.

-Connections default to an 8k outgoing maximum

### s2n\_connection\_get\_wire\_bytes

```c
uint64_t s2n_connection_get_wire_bytes_in(struct s2n_connection *conn);
uint64_t s2n_connection_get_wire_bytes_out(struct s2n_connection *conn);
```

**s2n_connection_get_wire_bytes_in** and **s2n_connection_get_wire_bytes_out**
return the number of bytes transmitted by s2n "on the wire", in and out
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
number actually used by s2n for the connection. **s2n_connection_get_client_hello_version**
returns the protocol version used in the initial client hello message.

Each version number value corresponds to the macros defined as **S2N_SSLv2**,
**S2N_SSLv3**, **S2N_TLS10**, **S2N_TLS11** and **S2N_TLS12**.

### s2n\_connection\_is\_client\_authenticated

```c
int s2n_connection_is_client_authenticated(struct s2n_connection *conn);
```
**s2n_connection_is_client_authenticated** returns 1 if the handshake completed and Client Auth was 
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

### s2n\_connection\_get\_alert

```c
int s2n_connection_get_alert(struct s2n_connection *conn);
```

If a connection was shut down by the peer, **s2n_connection_get_alert** returns
the TLS alert code that caused a connection to be shut down. s2n considers all
TLS alerts fatal and shuts down a connection whenever one is received.

### s2n\_connection\_get\_cipher

```c
const char * s2n_connection_get_cipher(struct s2n_connection *conn);
```

**s2n_connection_get_cipher** returns a string indicating the cipher suite
negotiated by s2n for a connection in Openssl format, e.g. "ECDHE-RSA-AES128-GCM-SHA256".

### s2n\_connection\_get\_curve

```c
const char * s2n_connection_get_curve(struct s2n_connection *conn);
```

**s2n_connection_get_curve** returns a string indicating the elliptic curve used during ECDHE key exchange. The string "NONE" is returned if no curve has was used.

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

## I/O functions

s2n supports both blocking and non-blocking I/O. To use s2n in non-blocking
mode, set the underlying file descriptors as non-blocking (i.e. with
**fcntl**). In blocking mode, each s2n I/O function will not return until it is
complete. In non-blocking mode an s2n I/O function may return while there is
still I/O pending. In this case the value of the **blocked** parameter will be set
to either **S2N_BLOCKED_ON_READ** or **S2N_BLOCKED_ON_WRITE**, depending on the
direction in which s2n is blocked.

s2n I/O functions should be called repeatedly until the **blocked** parameter is
**S2N_NOT_BLOCKED**. 

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

### s2n\_connection\_set\_send\_cb

```c
int s2n_connection_set_recv_cb(struct s2n_connection *conn, s2n_connection_recv recv);
int s2n_connection_set_send_cb(struct s2n_connection *conn, s2n_connection_send send);
int s2n_connection_set_recv_ctx(struct s2n_connection *conn, void *ctx);
int s2n_connection_set_send_ctx(struct s2n_connection *conn, void *ctx);
```

s2n also provides an I/O abstraction layer in the event the application would
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

# Examples

To understand the API it may be easiest to see examples in action. s2n's [bin/](https://github.com/awslabs/s2n/blob/master/bin/) directory
includes an example client (s2nc) and server (s2nd).

