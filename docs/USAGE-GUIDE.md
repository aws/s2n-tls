# Using s2n

s2n is a C library, and is built using Make. To clone the latest
copy of s2n from git use:

    git clone https://github.com/awslabs/s2n.git
    cd s2n

s2n depends on a local copy of libcrypto for certain ciphers.

## Building s2n with LibreSSL

To build s2n with LibreSSL, do the following:

    # We keep the build artifacts in the -build directory
    cd libcrypto-build

    # Download the latest version of LibreSSL
    curl http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-x.y.z.tar.gz > libressl-x.y.z.tar.gz
    tar -xzvf libressl-x.y.z.tar.gz

    # Build LibreSSL's libcrypto
    cd libressl-x.y.z
    ./configure --prefix=`pwd`/../../libcrypto-root/
    make
    make install

    # Make to the main s2n directory
    cd ../../

    # Build s2n
    make

once built, static and dynamic libraries for s2n will be available in the lib/
directory.

## Building s2n with OpenSSL-1.0.2

To build s2n with OpenSSL-1.0.2, do the following:

    # We keep the build artifacts in the -build directory
    cd libcrypto-build

    # Download the latest version of OpenSSL
    curl https://www.openssl.org/source/openssl-1.0.2.tar.gz > openssl-1.0.2.tar.gz
    tar -xzvf openssl-1.0.2.tar.gz

    # Build openssl' libcrypto
    cd openssl-1.0.2
    ./config -fPIC no-shared no-libunbound no-gmp no-jpake no-krb5              \
             no-md2 no-rc5 no-rfc3779 no-sctp no-ssl-trace no-store no-zlib     \
             no-hw no-mdc2 no-seed no-idea enable-ec-nist_64_gcc_128 no-camellia\ 
             no-bf no-ripemd no-dsa no-ssl2 no-ssl3 no-capieng                  \
             -DSSL_FORBID_ENULL -DOPENSSL_NO_DTLS1 -DOPENSSL_NO_HEARTBEATS      \
             --prefix=`pwd`/../../libcrypto-root/
    make depend
    make -j 32
    make install

    # Make to the main s2n directory
    cd ../../

    # Build s2n
    make

**Mac Users:** please replace "./config" with "./Configure darwin64-x86_64-cc".

once built, static and dynamic libraries for s2n will be available in the lib/
directory.

## mlock() and system limits 

Internally s2n uses mlock() to prevent memory from being swapped to disk. The
s2n build tests may fail in some environments where the default limit on locked
memory is too low. To check this limit, run:

    ulimit -l

to raise the limit, consult the documentation for your platform.

# s2n API

The API exposed by s2n is the set of functions and declarations that
are in the "s2n.h" header file. Other functions and structures used in s2n
internally can not be considered stable and their parameters, names, sizes and
so on may change.

## Preprocessor macros

s2n defines five preprocessor macros that are used to determine what 
version of SSL/TLS is in use on a connection. 

    #define S2N_SSLv2 20
    #define S2N_SSLv3 30
    #define S2N_TLS10 31
    #define S2N_TLS11 32
    #define S2N_TLS12 33

These correspond to SSL2.0, SSL3.0, TLS1.0, TLS1.1 and TLS1.2 respectively.
Note that s2n does not support SSL2.0 for sending and receiving encrypted data,
but does accept SSL2.0 hello messages.

## Enums

s2n defines two enum type:

    typedef enum { S2N_SERVER, S2N_CLIENT } s2n_mode;

**s2n_mode** is used to declare connections as server or client type,
respectively.  At this time, s2n does not function as a client and only
S2N_SERVER should be used.

    typedef enum { S2N_BUILT_IN_BLINDING, S2N_SELF_SERVICE_BLINDING } s2n_blinding;

**s2n_blinding** is used to opt-out of s2n's built-in blinding. By default s2n
will cause a thread to sleep between 1ms and 10 seconds when a tamper evident
record is encountered. S2N_SELF_SERVICE_BLINDING can be used to opt out of this
behaviour. If s2n_recv() returns an error, self-service applications should
call **s2n_connection_get_delay** and pause for the specified number of
microseconds before calling close() or shutdown().

## Opaque structures

s2n defines two opaque structures that are used for managed objects. These
structures are opaque and can only be safely referenced indirectly through
pointers. 

    struct s2n_config;
    struct s2n_connection;

**s2n_config** structures are a configuration object, used by servers for
holding cryptographic certificates, keys and preferences. **s2n_connection**
structures are used to track each connection.

## Error handling

s2n functions that return 'int' return 0 to indicate success and -1 to indicate
failure. s2n functions that return pointer types return NULL in the case of
failure. When an s2n function returns a failure, s2n_errno will be set to a value
corresponding to the error. This error value can be translated into a string 
explaining the error by calling s2n_strerror(s2n_errno, "EN"); 

## Configuration-oriented functions

### s2n\_config\_new

    struct s2n_config * s2n_config_new()

**s2n_config_new** returns a new configuration object suitable for associating certs and keys.
This object can (and should) be associated with many connection objects. 

### s2n\_config\_free

    struct int s2n_config_free(struct s2n_config *config)

**s2n_config_free** frees the memory associated with an **s2n_config** object.

### s2n\_config\_add\_cert\_chain\_and\_key

    int s2n_config_add_cert_chain_and_key(struct s2n_config *config, 
                                          char *cert_chain_pem, 
                                          char *private_key_pem);

**s2n_config_add_cert_chain_and_key** associates a certificate chain and a
private key, with an **s2n_config** object. At present, only one
certificate-chain/key pair may be associated with a config.

**cert_chain_pem** should be a PEM encoded certificate chain, with the first
certificate in the chain being your servers certificate. **private_key_pem**
should be a PEM encoded private key corresponding to the server certificate.

### s2n\_config\_add\_dhparams

    int s2n_config_add_dhparams(struct s2n_config *config, 
                                char *dhparams_pem)

**s2n_config_add_dhparams** associates a set of Diffie-Hellman parameters with
an **s2n_config** object. **dhparams_pem** should be PEM encoded DH parameters.

### s2n\_config\_set\_protocol\_preferences

    int s2n_config_set_protocol_preferences(struct s2n_config *config,
                                            const char **protocols,
                                            int protocol_count)

***s2n_config_set_protocol_preferences*** sets the application protocol
preferences on an **s2n_config** object.  **protocols** is a list in order of
preference, with most preferred protocol first, and of length
**protocol_count**.  When acting as an **S2N_CLIENT** the protocol list is
included in the Client Hello message as the ALPN extension.  As an
**S2N_SERVER**, the list is used to negotiate a mutual application protocol
with the client.

## Connection-oriented functions

### s2n\_connection\_new

    struct s2n_connection * s2n_connection_new(s2n_mode mode);

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

    int s2n_connection_set_config(struct s2n_connection *conn, 
                                  struct s2n_config *config);

**s2n_connection_set_config** Associates a configuration object with a
connection. 

### s2n\_connection\_set\_fd

    int s2n_connection_set_fd(struct s2n_connection *conn, 
                              int readfd)
    int s2n_connection_set_read_fd(struct s2n_connection *conn, 
                                   int readfd)
    int s2n_connection_set_write_fd(struct s2n_connection *conn, 
                                    int writefd);

**s2n_connection_set_fd** sets the file-descriptor for an s2n connection. This
file-descriptor should be active and connected. s2n also supports setting the
read and write file-descriptors to different values (for pipes or other unusual
types of I/O).

### s2n\_set\_server\_name

    int s2n_set_server_name(struct s2n_connection *conn, 
                            const char *server_name);

**s2n_set_server_name** Sets the server name for the connection. In future,
this can be used by clients who wish to use the TLS "Server Name indicator"
extension. At present, client functionality is disabled.

### s2n\_get\_server\_name

    const char *s2n_get_server_name(struct s2n_connection *conn);

**s2n_get_server_name** returns the server name associated with a connection,
or NULL if none is found. This can be used by a server to determine which server
name the client is using.

### s2n\_connection\_set\_blinding

    int s2n_connection_set_blinding(struct s2n_connection *conn, s2n_blinding blinding);

**s2n_connection_set_blinding** can be used to configure s2n to either use
built-in blinding (set blinding to S2N_BUILT_IN_BLINDING) or self-service blinding
(set blinding to S2N_SELF_SERVICE_BLINDING). 

### s2n\_connection\_get\_delay

    int s2n_connection_get_delay(struct s2n_connection *conn);

**s2n_connection_get_delay** returns the number of microseconds an application
using self-service blinding should pause before calling close() or shutdown().

### s2n\_connection\_get\_wire\_bytes

    uint64_t s2n_connection_get_wire_bytes_in(struct s2n_connection *conn);
    uint64_t s2n_connection_get_wire_bytes_out(struct s2n_connection *conn);

**s2n_connection_get_wire_bytes_in** and **s2n_connection_get_wire_bytes_out**
return the number of bytes transmitted by s2n "on the wire", in and out
respestively. 

### s2n\_connection\_get\_protocol\_version

    int s2n_connection_get_client_hello_version(struct s2n_connection *conn);
    int s2n_connection_get_client_protocol_version(struct s2n_connection *conn);
    int s2n_connection_get_server_protocol_version(struct s2n_connection *conn);
    int s2n_connection_get_actual_protocol_version(struct s2n_connection *conn);
    
**s2n_connection_get_client_protocol_version** returns the protocol version
number supported by the client, **s2n_connection_get_server_protocol_version**
returns the protocol version number supported by the server and
**s2n_connection_get_actual_protocol_version** returns the protocol version
number actually used by s2n for the connection. **s2n_connection_get_client_hello_version**
returns the protocol version used in the initial client hello message.

Each version number value corresponds to the macros defined as **S2N_SSLv2**,
**S2N_SSLv3**, **S2N_TLS10**, **S2N_TLS11** and **S2N_TLS12**.

### s2n\_get\_application\_protocol

    const char *s2n_get_application_protocol(struct s2n_connection *conn)

**s2n_get_application_protocol** returns the negotiated application protocol
for a **s2n_connection**.  In the event of no protocol being negotiated, NULL
is returned.

### s2n\_connection\_get\_alert

    int s2n_connection_get_alert(struct s2n_connection *conn);

If a connection was shut down by the peer, **s2n_connection_get_alert** returns
the TLS alert code that caused a connection to be shut down. s2n considers all
TLS alerts fatal and shuts down a connection whenever one is received.

### s2n\_connection\_get\_cipher

    const char * s2n_connection_get_cipher(struct s2n_connection *conn);
    
**s2n_connection_get_cipher** returns a string indicating the cipher suite
negotiated by s2n for a connection, e.g. "TLS\_RSA\_WITH\_AES\_128\_CBC\_SHA".

### s2n\_connection\_wipe

    int s2n_connection_wipe(struct s2n_connection *conn);

**s2n_connection_wipe** erases all data associated with a connection including
pending reads.

### s2n\_connection\_free

    int s2n_connection_free(struct s2n_connection *conn);

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

    int s2n_negotiate(struct s2n_connection *conn, int *more);

**s2n_negotiate** performs the initial "handshake" phase of a TLS connection and must be called before any **s2n_recv** or **s2n_send** calls. 

### s2n\_send

    ssize_t s2n_send(struct s2n_connection *conn 
                  void *buf,
                  ssize_t size,
                  int *more);

**s2n_send** writes and encrypts **size* of **buf** data to the associated connection. **s2n_send** will return the number of bytes written, and may indicate a partial write. Partial writes are possible not just for non-blocking I/O, but also for connections aborted while active. **NOTE:** Unlike OpenSSL, repeated calls to **s2n_send** should not duplicate the original parameters, but should update **buf** and **size** per the indication of size written. For example;

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
    

### s2n\_recv

    ssize_t s2n_recv(struct s2n_connection *conn,
                 void *buf,
                 ssize_t size,
                 int *more);

**s2n_recv** decrypts and reads **size* to **buf** data from the associated
connection. **s2n_recv** will return the number of bytes read and also return
"0" on connection shutdown by the peer.

**NOTE:** Unlike OpenSSL, repeated calls to **s2n_recv** should not duplicate the original parameters, but should update **buf** and **size** per the indication of size read. For example;

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

### s2n_shutdown

    int s2n_shutdown(struct s2n_connection *conn,
                     int *more);

**s2n_shutdown** shuts down the s2n connection. Once a connection has been shut down it is not available for reading or writing.

# Examples

To understand the API it may be easiest to see examples in action.

## Example server

This example server reads a single HTTP request (over HTTPS) and then responds with a trivial HTML response.

    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include <sys/poll.h>
    #include <netdb.h>

    #include <stdlib.h>
    #include <unistd.h>
    #include <string.h>
    #include <stdio.h>

    #include <errno.h>

    #include <s2n.h>

    static char certificate[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDLjCCAhYCCQDL1lr6N8/gvzANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJB\n"
    "VTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0\n"
    "cyBQdHkgTHRkMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMTQwNTEwMTcwODIzWhcN\n"
    "MjQwNTA3MTcwODIzWjBZMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0\n"
    "ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQDEwls\n"
    "b2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIltaUmHg+\n"
    "G7Ida2XCtEQx1YeWDX41U2zBKbY0lT+auXf81cT3dYTdfJblb+v4CTWaGNofogcz\n"
    "ebm8B2/OF9F+WWkKAJhKsTPAE7/SNAdi4Eqv4FfNbWKkGb4xacxxb4PH2XP9V3Ch\n"
    "J6lMSI3V68FmEf4kcEN14V8vufIC5HE/LT4gCPDJ4UfUUbAgEhSebT6r/KFYB5T3\n"
    "AeDc1VdnaaRblrP6KwM45vTs0Ii09/YrlzBxaTPMjLGCKa8JMv8PW2R0U9WCqHmz\n"
    "BH+W3Q9xPrfhCInm4JWob8WgM1NuiYuzFB0CNaQcdMS7h0aZEAVnayhQ96/Padpj\n"
    "KNE0Lur9nUxbAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAGRV71uRt/1dADsMD9fg\n"
    "JvzW89jFAN87hXCRhTWxfXhYMzknxJ5WMb2JAlaMc/gTpiDiQBkbvB+iJe5AepgQ\n"
    "WbyxPJNtSlA9GfKBz1INR5cFsOL27VrBoMYHMaolveeslc1AW2HfBtXWXeWSEF7F\n"
    "QNgye8ZDPNzeSWSI0VyK2762wsTgTuUhHAaJ45660eX57+e8IvaM7xOEfBPDKYtU\n"
    "0a28ZuhvSr2akJtGCwcs2J6rs6I+rV84UktDxFC9LUezBo8D9FkMPLoPKKNH1dXR\n"
    "6LO8GOkqWUrhPIEmfy9KYes3q2ZX6svk4rwBtommHRv30kPxnnU1YXt52Ri+XczO\n"
    "wEs=\n"
    "-----END CERTIFICATE-----\n";
    
    static char private_key[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAyJbWlJh4PhuyHWtlwrREMdWHlg1+NVNswSm2NJU/mrl3/NXE\n"
    "93WE3XyW5W/r+Ak1mhjaH6IHM3m5vAdvzhfRfllpCgCYSrEzwBO/0jQHYuBKr+BX\n"
    "zW1ipBm+MWnMcW+Dx9lz/VdwoSepTEiN1evBZhH+JHBDdeFfL7nyAuRxPy0+IAjw\n"
    "yeFH1FGwIBIUnm0+q/yhWAeU9wHg3NVXZ2mkW5az+isDOOb07NCItPf2K5cwcWkz\n"
    "zIyxgimvCTL/D1tkdFPVgqh5swR/lt0PcT634QiJ5uCVqG/FoDNTbomLsxQdAjWk\n"
    "HHTEu4dGmRAFZ2soUPevz2naYyjRNC7q/Z1MWwIDAQABAoIBAHrkryLrJwAmR8Hu\n"
    "grH/b6h4glFUgvZ43jCaNZ+RsR5Cc1jcP4i832Izat+26oNUYRrADyNCSdcnxLuG\n"
    "cuF5hkg6zzfplWRtnJ8ZenR2m+/gKuIGOMULN1wCyZvMjg0RnVNbzsxwPfj+K6Mo\n"
    "8H0Xq621aFc60JnwMjkzWyqaeyeQogn1pqybuL6Dm2huvN49LR64uHuDUStTRX33\n"
    "ou1fVWXOJ1kealYPbRPj8pDa31omB8q5Cf8Qe/b9anqyi9CsP17QbVg9k2IgoLlj\n"
    "agqOc0u/opOTZB4tqJbqsIdEhc5LD5RUkYJsw00Iq0RSiKTfiWSPyOFw99Y9Act0\n"
    "cbIIxEECgYEA8/SOsQjoUX1ipRvPbfO3suV1tU1hLCQbIpv7WpjNr1kHtngjzQMP\n"
    "dU/iriUPGF1H+AxJJcJQfCVThV1AwFYVKb/LCrjaxlneZSbwfehpjo+xQGaNYG7Q\n"
    "1vQuBVejuYk/IvpZltQOdm838DjvYyWDMh4dcMFIycXxEg+oHxf/s+8CgYEA0n4p\n"
    "GBuLUNx9vv3e84BcarLaOF7wY7tb8z2oC/mXztMZpKjovTH0PvePgI5/b3KQ52R0\n"
    "8zXHVX/4lSQVtCuhOVwKOCQq97/Zhlp5oTTShdQ0Qa1GQRl5wbTS6hrYEWSi9AQP\n"
    "BVUPZ+RIcxx00DfBNURkId8xEpvCOmvySN8sUlUCgYAtXmHbEqkB3qulwRJGhHi5\n"
    "UGsfmJBlwSE6wn9wTdKStZ/1k0o1KkiJrJ2ffUzdXxuvSbmgyA5nyBlMSBdurZOp\n"
    "+/0qtU4abUQq058OC1b2KEryix/nuzQjha25WJ8eNiQDwUNABZfa9rwUdMIwUh2g\n"
    "CHG5Mnjy7Vjz3u2JOtFXCQKBgQCVRo1EIHyLauLuaMINM9HWhWJGqeWXBM8v0GD1\n"
    "pRsovQKpiHQNgHizkwM861GqqrfisZZSyKfFlcynkACoVmyu7fv9VoD2VCMiqdUq\n"
    "IvjNmfE5RnXVQwja+668AS+MHi+GF77DTFBxoC5VHDAnXfLyIL9WWh9GEBoNLnKT\n"
    "hVm8RQKBgQCB9Skzdftc+14a4Vj3NCgdHZHz9mcdPhzJXUiQyZ3tYhaytX9E8mWq\n"
    "pm/OFqahbxw6EQd86mgANBMKayD6B1Id1INqtXN1XYI50bSs1D2nOGsBM7MK9aWD\n"
    "JXlJ2hwsIc4q9En/LR3GtBaL84xTHGfznNylNhXi7GbO1wNMJuAukA==\n"
    "-----END RSA PRIVATE KEY-----\n";

    static char dhparams[] =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEAy1+hVWCfNQoPB+NA733IVOONl8fCumiz9zdRRu1hzVa2yvGseUSq\n"
    "Bbn6k0FQ7yMED6w5XWQKDC0z2m0FI/BPE3AjUfuPzEYGqTDf9zQZ2Lz4oAN90Sud\n"
    "luOoEhYR99cEbCn0T4eBvEf9IUtczXUZ/wj7gzGbGG07dLfT+CmCRJxCjhrosenJ\n"
    "gzucyS7jt1bobgU66JKkgMNm7hJY4/nhR5LWTCzZyzYQh2HM2Vk4K5ZqILpj/n0S\n"
    "5JYTQ2PVhxP+Uu8+hICs/8VvM72DznjPZzufADipjC7CsQ4S6x/ecZluFtbb+ZTv\n"
    "HI5CnYmkAwJ6+FSWGaZQDi8bgerFk9RWwwIBAg==\n"
    "-----END DH PARAMETERS-----\n";

    static char response[] =
    "HTTP/1.0 200 OK\r\n"
    "Content-Length: 34\r\n"
    "Connection: close\r\n"
    "Content-Type: text/html; charset=utf-8\r\n\r\n"
    "<html><h1>Hello World!</h1></html>";

    void usage()
    {
        fprintf(stderr, "usage: example_https_server ip port\n");
        fprintf(stderr, " host: hostname or IP address to listen on\n");
        fprintf(stderr, " port: hostname or IP address to listen on\n");

        exit(1);
    }

    int main(int argc, const char *argv[])
    {
        struct addrinfo hints, *ai;
        int r, sockfd = 0;
        int more;

        if (argc != 3) {
            usage();
        }

        if (memset(&hints, 0, sizeof(hints)) != &hints) {
            fprintf(stderr, "memset error: %s\n", strerror(errno));
            return -1;
        }

        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if ((r = getaddrinfo(argv[1], argv[2], &hints, &ai)) != 0) {
            fprintf(stderr, "error: %s\n", gai_strerror(r));
            return -1;
        }

        if ((sockfd = socket(ai->ai_family, ai->ai_socktype,
                             ai->ai_protocol)) == -1) {
            exit(1);
        }

        r = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &r, sizeof(int)) < 0) {
            exit(1);
        }

        if (bind(sockfd, ai->ai_addr, ai->ai_addrlen) < 0) {
            exit(1);
        }

        if (listen(sockfd, 1) == -1) {
            exit(1);
        }
        struct s2n_config *config = s2n_config_new();
        if (!config) {
            fprintf(stderr, "Error getting new s2n config: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            exit(1);
        }

        if (s2n_config_add_cert_chain_and_key(config, "_default_", certificate, 
                                              private_key) < 0) {
            fprintf(stderr, "Error getting certificate/key: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            exit(1);
        }

        if (s2n_config_add_dhparams(config, dhparams) < 0) {
            fprintf(stderr, "Error adding DH parameters: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            exit(1);
        }

        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);

        if (s2n_connection_set_config(conn, config) < 0) {
            fprintf(stderr, "Error setting configuration: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            exit(1);
        }

        int fd;
        while ((fd = accept(sockfd, ai->ai_addr, &ai->ai_addrlen)) > 0) {
            if (s2n_connection_set_fd(conn, fd) < 0) {
                fprintf(stderr, "Error setting file descriptor: '%s'\n", s2n_strerror(s2n_errno, "EN"));
                exit(1);
            }

            if (s2n_negotiate(conn, &more) < 0) {
                fprintf(stderr, "Error negotiating: '%s'\n", s2n_strerror(s2n_errno, "EN"));
                s2n_connection_wipe(conn);
                continue;
            }

            if (s2n_get_server_name(conn)) {
                printf("Got connection with server name: '%s'\n",
                       s2n_get_server_name(conn));
            }
            else {
                printf("Got connection with no server name\n");
            }

            if (s2n_send(conn, response, sizeof(response), &more) < 0) {
                s2n_connection_wipe(conn);
                continue;
            }

            s2n_shutdown(conn, &more);
            s2n_connection_wipe(conn);
        }
        
        return 0;
    }
