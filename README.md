<img src="docs/images/s2n_logo_github.png" alt="s2n">

s2n-tls is a C99 implementation of the TLS/SSL protocols that is designed to be simple, small, fast, and with security as a priority. It is released and licensed under the Apache License 2.0.

> s2n-tls is short for "signal to noise" and is a nod to the almost magical act of encryption — disguising meaningful signals, like your critical data, as seemingly random noise.
>
> -- [s2n-tls announcement](https://aws.amazon.com/blogs/security/introducing-s2n-a-new-open-source-tls-implementation/)

[![Build Status](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiMndlTzJNbHVxWEo3Nm82alp4eGdGNm4rTWdxZDVYU2VTbitIR0ZLbHVtcFFGOW5majk5QnhqaUp3ZEkydG1ueWg0NGlhRE43a1ZnUzZaQTVnSm91TzFFPSIsIml2UGFyYW1ldGVyU3BlYyI6IlJLbW42NENlYXhJNy80QnYiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=main)](https://github.com/aws/s2n-tls/)
[![Apache 2 License](https://img.shields.io/github/license/aws/s2n-tls.svg)](http://aws.amazon.com/apache-2-0/)
[![C99](https://img.shields.io/badge/language-C99-blue.svg)](http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1256.pdf)
[![Github forks](https://img.shields.io/github/forks/aws/s2n-tls.svg)](https://github.com/aws/s2n-tls/network)
[![Github stars](https://img.shields.io/github/stars/aws/s2n-tls.svg)](https://github.com/aws/s2n-tls/stargazers)
[![Join the chat at https://gitter.im/awslabs/s2n](https://badges.gitter.im/awslabs/s2n.svg)](https://gitter.im/awslabs/s2n?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## Quickstart for Ubuntu
1. Fork s2n-tls on GitHub
2. Run the following commands on Ubuntu.
```
git clone https://github.com/${YOUR_GITHUB_ACCOUNT_NAME}/s2n-tls.git
cd s2n-tls

# Pick an "env" line from the codebuild/codebuild.config file and run it, in this case choose the openssl-1.1.1 with GCC 9 build
S2N_LIBCRYPTO=openssl-1.1.1 BUILD_S2N=true TESTS=integrationv2 GCC_VERSION=9

sudo codebuild/bin/s2n_install_test_dependencies.sh
codebuild/bin/s2n_codebuild.sh
```

## Quickstart for OSX (or other platforms)

If you are building on OSX, or simply don't want to execute the entire build script above, you can use build tools like Ninja.

### OSX

An example of building on OSX:

```sh
# Install required dependencies using homebrew
brew install ninja cmake coreutils openssl@1.1

# Clone the s2n-tls source repository into the `s2n-tls` directory
git clone https://github.com/${YOUR_GITHUB_ACCOUNT_NAME}/s2n-tls.git
cd s2n-tls

# Create a build directory, and build s2n-tls with debug symbols and a specific OpenSSL version.
cmake . -Bbuild -GNinja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_PREFIX_PATH=$(dirname $(dirname $(brew list openssl@1.1|grep libcrypto.dylib)))
cmake --build ./build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) ninja -C build test
```

### Amazonlinux2

Install dependencies with `./codebuild/bin/install_al2_dependencies.sh` after cloning.

```sh
git clone https://github.com/${YOUR_GITHUB_ACCOUNT_NAME}/s2n-tls.git
cd s2n-tls
cmake . -Bbuild -DCMAKE_EXE_LINKER_FLAGS="-lcrypto -lz" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build ./build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) make -C build test
```

## Have a Question?
If you have any questions about Submitting PR's, Opening Issues, s2n-tls API usage, or something similar, we have a public chatroom available here to answer your questions: https://gitter.im/awslabs/s2n

Otherwise, if you think you might have found a security impacting issue, please instead follow [our Security Notification Process.](#security-issue-notifications)

## Documentation

s2n-tls uses [Doxygen](https://doxygen.nl/index.html) to document its public API. The latest s2n-tls documentation can be found on [GitHub pages](https://aws.github.io/s2n-tls/doxygen/). The [Usage Guide](docs/USAGE-GUIDE.md) explains how different TLS features can be configured and used.

Documentation for older versions or branches of s2n-tls can be generated locally. To generate the documentation, install doxygen and run `doxygen docs/doxygen/Doxyfile`. The doxygen documentation can now be found at `docs/doxygen/output/html/index.html`.

Doxygen installation instructions are available at the [Doxygen](https://doxygen.nl/download.html) webpage.

## Using s2n-tls

The s2n-tls I/O APIs are designed to be intuitive to developers familiar with the widely-used POSIX I/O APIs, and s2n-tls supports blocking, non-blocking, and full-duplex I/O. Additionally there are no locks or mutexes within s2n-tls.

```c
/* Create a server mode connection handle */
struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
if (conn == NULL) {
    ... error ...
}

/* Associate a connection with a file descriptor */
if (s2n_connection_set_fd(conn, fd) < 0) {
    ... error ...
}

/* Negotiate the TLS handshake */
s2n_blocked_status blocked;
if (s2n_negotiate(conn, &blocked) < 0) {
    ... error ...
}

/* Write data to the connection */
int bytes_written;
bytes_written = s2n_send(conn, "Hello World", sizeof("Hello World"), &blocked);
```

For details on building the s2n-tls library and how to use s2n-tls in an application you are developing, see the [usage guide](https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md).

## s2n-tls features

s2n-tls implements SSLv3, TLS1.0, TLS1.1, TLS1.2, and TLS1.3. For encryption, s2n-tls supports 128-bit and 256-bit AES in the CBC and GCM modes, ChaCha20, 3DES, and RC4. For forward secrecy, s2n-tls supports both DHE and ECDHE. s2n-tls also supports the Server Name Indicator (SNI), Application-Layer Protocol Negotiation (ALPN), and Online Certificate Status Protocol (OCSP) TLS extensions. SSLv3, RC4, 3DES, and DHE are each disabled by default for security reasons.

As it can be difficult to keep track of which encryption algorithms and protocols are best to use, s2n-tls features a simple API to use the latest "default" set of preferences. If you prefer to remain on a specific version for backwards compatibility, that is also supported.

```c
/* Use the latest s2n-tls "default" set of ciphersuite and protocol preferences */
s2n_config_set_cipher_preferences(config, "default");

/* Use a specific set of preferences, update when you're ready */
s2n_config_set_cipher_preferences(config, "20150306")
```

## s2n-tls safety mechanisms

Internally s2n-tls takes a systematic approach to data protection and includes several mechanisms designed to improve safety.

##### Small and auditable code base
Ignoring tests, blank lines and comments, s2n-tls is about 6,000 lines of code. s2n's code is also structured and written with a focus on reviewability. All s2n-tls code is subject to code review, and we plan to complete security evaluations of s2n-tls on an annual basis.

To date there have been two external code-level reviews of s2n-tls, including one by a commercial security vendor. s2n-tls has also been shared with some trusted members of the broader cryptography, security, and Open Source communities. Any issues discovered are always recorded in the s2n-tls issue tracker.

##### Static analysis, fuzz-testing and penetration testing

In addition to code reviews, s2n-tls is subject to regular static analysis, fuzz-testing, and penetration testing. Several penetration tests have occurred, including two by commercial vendors.

##### Unit tests and end-to-end testing

s2n-tls includes positive and negative unit tests and end-to-end test cases.

##### Erase on read
s2n-tls encrypts or erases plaintext data as quickly as possible. For example, decrypted data buffers are erased as they are read by the application.

##### Built-in memory protection
s2n-tls uses operating system features to protect data from being swapped to disk or appearing in core dumps.

##### Minimalist feature adoption
s2n-tls avoids implementing rarely used options and extensions, as well as features with a history of triggering protocol-level vulnerabilities. For example there is no support for session renegotiation or DTLS.

##### Compartmentalized random number generation
The security of TLS and its associated encryption algorithms depends upon secure random number generation. s2n-tls provides every thread with two separate random number generators. One for "public" randomly generated data that may appear in the clear, and one for "private" data that should remain secret. This approach lessens the risk of potential predictability weaknesses in random number generation algorithms from leaking information across contexts.

##### Modularized encryption
s2n-tls has been structured so that different encryption libraries may be used. Today s2n-tls supports OpenSSL (versions 1.0.2, 1.1.1 and 3.0.x), LibreSSL, BoringSSL, AWS-LC, and the Apple Common Crypto framework to perform the underlying cryptographic operations.

##### Timing blinding
s2n-tls includes structured support for blinding time-based side-channels that may leak sensitive data. For example, if s2n-tls fails to parse a TLS record or handshake message, s2n-tls will add a randomized delay of between 10 and 30 seconds, granular to nanoseconds, before responding. This raises the complexity of real-world timing side-channel attacks by a factor of at least tens of trillions.

##### Table based state-machines
s2n-tls uses simple tables to drive the TLS/SSL state machines, making it difficult for invalid out-of-order states to arise.

##### C safety
s2n-tls is written in C, but makes light use of standard C library functions and wraps all memory handling, string handling, and serialization in systematic boundary-enforcing checks.

## Security issue notifications
If you discover a potential security issue in s2n-tls we ask that you notify
AWS Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue.

If you package or distribute s2n-tls, or use s2n-tls as part of a large multi-user service, you may be eligible for pre-notification of future s2n-tls releases. Please contact s2n-pre-notification@amazon.com.

## Contributing to s2n-tls
If you are interested in contributing to s2n-tls, please see our [development guide](https://github.com/aws/s2n-tls/blob/main/docs/DEVELOPMENT-GUIDE.md).

## Language Bindings for s2n-tls
See our [language bindings list](https://github.com/aws/s2n-tls/blob/main/docs/BINDINGS.md) for language bindings for s2n-tls that we're aware of.
