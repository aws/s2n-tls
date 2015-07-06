# Using s2n

s2n is a C library, and is built using Make. To clone the latest
copy of s2n from git use:

```shell
git clone https://github.com/awslabs/s2n.git
cd s2n
```

s2n depends on a local copy of libcrypto for certain ciphers.

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

# Make to the main s2n directory
cd ../../

# Build s2n
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

## Building s2n with OpenSSL-1.0.2

To build s2n with OpenSSL-1.0.2, do the following:

```shell
# We keep the build artifacts in the -build directory
cd libcrypto-build

# Download the latest version of OpenSSL
curl -O https://www.openssl.org/source/openssl-1.0.2-latest.tar.gz
tar -xzvf openssl-1.0.2-latest.tar.gz

# Build openssl' libcrypto  (NOTE: check directory name 1.0.2-latest unpacked as)
cd openssl-1.0.2c
./config -fPIC no-shared no-libunbound no-gmp no-jpake no-krb5              \
         no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-store no-zlib     \
         no-hw no-mdc2 no-seed no-idea enable-ec-nist_64_gcc_128 no-camellia\
         no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng                  \
         -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
         --prefix=`pwd`/../../libcrypto-root/
make depend
make
make install

# Make to the main s2n directory
cd ../../

# Build s2n
make
```

**Mac Users:** please replace "./config" with "./Configure darwin64-x86_64-cc".

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

s2n defines three enum types:

```c
typedef enum { S2N_SERVER, S2N_CLIENT } s2n_mode;
```

**s2n_mode** is used to declare connections as server or client type,
respectively.  At this time, s2n does not function as a client and only
S2N_SERVER should be used.

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
activity on the connection  for the specified number of microseconds before calling
close() or shutdown().

```c
typedef enum { S2N_STATUS_REQUEST_NONE, S2N_STATUS_REQUEST_OCSP } s2n_status_request_type;
```

**s2n_status_request_type** is used to define the type, if any, of certificate
status request an S2N_CLIENT should make during the handshake. The only
supported status request type is OCSP, **S2N_STATUS_REQUEST_OCSP**.

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

## Error handling

s2n functions that return 'int' return 0 to indicate success and -1 to indicate
failure. s2n functions that return pointer types return NULL in the case of
failure. When an s2n function returns a failure, s2n_errno will be set to a value
corresponding to the error. This error value can be translated into a string 
explaining the error in English by calling s2n_strerror(s2n_errno, "EN"); 

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
struct int s2n_config_free(struct s2n_config *config);
```

**s2n_config_free** frees the memory associated with an **s2n_config** object.

### s2n\_config\_set\_protocol\_preferences

```c
int s2n_config_set_cipher_preferences(struct s2n_config *config,
                                      const char *version);
```

**s2n_config_set_cipher_preferences** sets the ciphersuite and protocol versions. The currently supported versions are;

|    version | SSLv3 | TLS1.0 | TLS1.1 | TLS1.2 | AES-CBC | AES-GCM | 3DES | RC4 | DHE | ECDHE |
|------------|-------|--------|--------|--------|---------|---------|------|-----|-----|-------|
| "default"  |       |   X    |    X   |    X   |    X    |    X    |  X   |     |     |   X   |
| "20150306" |       |   X    |    X   |    X   |    X    |    X    |  X   |     |     |   X   |
| "20150214" |       |   X    |    X   |    X   |    X    |    X    |  X   |     |  X  |       |
| "20150202" |       |   X    |    X   |    X   |    X    |         |  X   |     |  X  |       |
| "20141001" |       |   X    |    X   |    X   |    X    |         |  X   |  X  |  X  |       |
| "20140601" |   X   |   X    |    X   |    X   |    X    |         |  X   |  X  |  X  |       |

The "default" version is special in that it will be updated with future s2n changes and ciphersuites and protocol versions may be added and removed, or their internal order of preference might change. Numbered versions are fixed and will never change. 

s2n does not expose an API to control the order of preference for each ciphersuite or protocol version. s2n follows the following order:

1. Always prefer the highest protocol version supported
2. Always use forward secrecy where possible. Prefer ECDHE over DHE. 
3. Prefer encryption ciphers in the following order: AES128, 3DES, AES256, RC4.
4. Prefer record authentication modes in the following order: GCM, SHA256, SHA1, MD5.

### s2n\_config\_add\_cert\_chain\_and\_key

```c
int s2n_config_add_cert_chain_and_key(struct s2n_config *config, 
                                      char *cert_chain_pem, 
                                      char *private_key_pem);
```

**s2n_config_add_cert_chain_and_key** associates a certificate chain and a
private key, with an **s2n_config** object. At present, only one
certificate-chain/key pair may be associated with a config.

**cert_chain_pem** should be a PEM encoded certificate chain, with the first
certificate in the chain being your servers certificate. **private_key_pem**
should be a PEM encoded private key corresponding to the server certificate.

### s2n\_config\_add\_cert\_chain\_and\_key\_with\_status

```c
int s2n_config_add_cert_chain_and_key_with_status(struct s2n_config *config, 
                                                  char *cert_chain_pem, 
                                                  char *private_key_pem,
                                                  const uint8_t *status,
                                                  uint32_t length);
```

**s2n_config_add_cert_chain_and_key_with_status** performs the same function
as s2n_config_add_cert_chain_and_key, and associates an OCSP status response
with the server certificate.  If a client requests the OCSP status of the server
certificate, this is the response used in the CertificateStatus handshake
message.

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
with the client.

### s2n\_config\_set\_status\_request\_type

```c
int s2n_config_set_status_request_type(struct s2n_config *config, s2n_status_request_type type);
```

**s2n_config_set_status_request_type** Sets up an S2N_CLIENT to request the
server certificate status during an SSL handshake.  If set to
S2N_STATUS_REQUEST_NONE, no status request is made.

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
ensure that only one sender or reciever is active at a time. The **mode**
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
int s2n_connection_get_delay(struct s2n_connection *conn);
```

**s2n_connection_get_delay** returns the number of microseconds an application
using self-service blinding should pause before calling close() or shutdown().

### s2n\_connection\_get\_wire\_bytes

```c
uint64_t s2n_connection_get_wire_bytes_in(struct s2n_connection *conn);
uint64_t s2n_connection_get_wire_bytes_out(struct s2n_connection *conn);
```

**s2n_connection_get_wire_bytes_in** and **s2n_connection_get_wire_bytes_out**
return the number of bytes transmitted by s2n "on the wire", in and out
respestively. 

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
negotiated by s2n for a connection, e.g. "TLS\_RSA\_WITH\_AES\_128\_CBC\_SHA".

### s2n\_connection\_wipe

```c
int s2n_connection_wipe(struct s2n_connection *conn);
```

**s2n_connection_wipe** erases all data associated with a connection including
pending reads.

### s2n\_connection\_free

```c
int s2n_connection_free(struct s2n_connection *conn);
```

**s2n_connection_free** frees the memory associated with an s2n_connection
handle.

## I/O functions

s2n supports both blocking and non-blocking I/O. To use s2n in non-blocking
mode, set the underlying file descriptors as non-blocking (i.e. with
**fcntl**). In blocking mode, each s2n I/O function will not return until it is
complete. In non-blocking mode an s2n I/O function may return while there is
still I/O pending. In this case the value of the **more** parameter will be set
to 1.

s2n I/O functions should be called repeatedly until the **more** parameter is
zero. 

### s2n\_negotiate

```c
int s2n_negotiate(struct s2n_connection *conn, int *more);
```

**s2n_negotiate** performs the initial "handshake" phase of a TLS connection and must be called before any **s2n_recv** or **s2n_send** calls.

### s2n\_send

```c
ssize_t s2n_send(struct s2n_connection *conn 
              void *buf,
              ssize_t size,
              int *more);
```

**s2n_send** writes and encrypts **size* of **buf** data to the associated connection. **s2n_send** will return the number of bytes written, and may indicate a partial write. Partial writes are possible not just for non-blocking I/O, but also for connections aborted while active. **NOTE:** Unlike OpenSSL, repeated calls to **s2n_send** should not duplicate the original parameters, but should update **buf** and **size** per the indication of size written. For example;

```c
int more, written = 0;
char data[10]; /* Some data we want to write */
do {
    int w = s2n_send(conn, data + written, 10 - written, &more);
    if (w < 0) {
        /* Some kind of error */
        break;
    }
    written += w;
} while (more); 
```    

### s2n\_recv

```c
ssize_t s2n_recv(struct s2n_connection *conn,
             void *buf,
             ssize_t size,
             int *more);
```

**s2n_recv** decrypts and reads **size* to **buf** data from the associated
connection. **s2n_recv** will return the number of bytes read and also return
"0" on connection shutdown by the peer.

**NOTE:** Unlike OpenSSL, repeated calls to **s2n_recv** should not duplicate the original parameters, but should update **buf** and **size** per the indication of size read. For example;

```c
int more, bytes_read = 0;
char data[10];
do {
    int r = s2n_recv(conn, data + bytes_read, 10 - bytes_read, &more);
    if (r < 0) {
        /* Some kind of error */
        break;
    }
    bytes_read += r;
} while (more);
```

### s2n_shutdown

```c
int s2n_shutdown(struct s2n_connection *conn,
                 int *more);
```

**s2n_shutdown** shuts down the s2n connection. Once a connection has been shut down it is not available for reading or writing.

# Examples

To understand the API it may be easiest to see examples in action. s2n's [bin/](https://github.com/awslabs/s2n/blob/master/bin/) directory
includes an example client (s2nc) and server (s2nd).
