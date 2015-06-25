<img src="docs/images/s2n_logo_github.png" alt="s2n">

s2n is a C99 implementation of the TLS/SSL protocols that is designed to be simple, small, fast, and with security as a priority. It is released and licensed under the Apache Software License 2.0. 

## s2n features

s2n implements SSLv3, TLS1.0, TLS1.1 and TLS1.2. For encryption, s2n suppports 128-bit and 256-bit AES, in the CBC and GCM modes, 3DES and RC4. For forward secrecy, s2n supports both DHE and ECDHE. s2n also supports the Server Name Indicator (SNI), Application-Layer Protocol Negotiation (ALPN) and the Online Certificate Status Protocol (OCSP) TLS extensions. SSLv3, RC4 and DHE are each disabled by default for security reasons. 

As it can be difficult to keep track of which encryption algorithms and protocols are best to use, s2n features a simple API to use the latest "default" set of preferences. If you prefer to remain on a specific version for backwards compatibility, that is supported too. 

    /* Use the latest "default" set of ciphersuite and protocol preferences */
    s2n_config_set_cipher_preferences(config, "default");
    
    /* Use a specific (i.e. tested) set of ciphersuite and protocol preferences */
    s2n_config_set_cipher_preferences(config, "20150306")

## Using s2n

The s2n I/O APIs are designed to be intuitive to developers familiar with the widely-used POSIX I/O APIs, and s2n supports blocking, non-blocking and full-duplex I/O. Additionally there are no locks or mutexes within s2n. 

For details on building the s2n library and how to use s2n in an application you are developing, see the [API Reference](https://github.com/awslabs/s2n/blob/master/docs/USAGE-GUIDE.md).

## s2n security mechanisms

Internally s2n takes a systematic approach to data protection and includes several mechanisms designed to improve safety.

##### Small and auditable code base
Ignoring tests, blank lines and comments, s2n is about 6,000 lines of code. s2n's code is also structured and written with a focus on reviewability. All s2n code is subject to code review, and we plan to complete security reviews of s2n on an anual basis.

To date there have been two external code-level reviews of s2n, including one by a commercial security vendor, and s2n has been shared with some members of the broader cryptography, security and Open Source communities. Any issues discovered are always recorded in the s2n issue tracker. 

##### Static analysis, fuzz-testing and penetration testing

In addition to code reviews, s2n is also subject to regular static analsys, fuzz-testing and penetration testing. Several penetration tests have occured, including two by commercial vendors.  

##### Erase on read
s2n encrypts or erases plaintext data as quickly as possible. For example, decrypted data buffers are erased as they are read by the application.

##### Built-in memory protection
s2n uses operating system features to protect data from being swapped to disk or appearing in core dumps.

##### Minimalist feature adoption
s2n avoids implementing rarely used options and extensions, as well as features with a history of triggering protocol-level vulnerabilities. For example there is no support for session renegotiation or DTLS.

##### Segmented random number generation
The security of TLS and its associated encryption algorithms depends upon secure random number generation. s2n provides every thread with two seperate random number generators. One for "public" randomly generated data which may appear in the clear, and one for "private" data which should remain secret. This approach lessens the risk of potential predictability weaknesses in random number generation algorithms from leaking information across contexts. 

##### Modularized encryption
s2n has been structured so that different encryption libraries may be used. Today s2n supports OpenSSL, LibreSSL, BoringSSL and the Apple Common Crypto framework to perform the underlying cryptographic operations.

##### Table based state-machines
s2n uses simple tables to drive the TLS/SSL state machines, making it difficult for invalid out-of-order states to arise. 

##### C safety
s2n is written in C, but makes light use of standard C library functions and wraps all memory handling, string handling and serialization in systematic boundary-enforcing checks. 

## Security issue notifications
If you discover a potential security issue in s2n we ask that you notify
AWS Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue. 

If you package or distribute s2n, or use s2n as part of a large multi-user service, you may be elligible for pre-notification of future s2n releases. Please contact s2n-pre-notification@amazon.com.  

## Contributing to s2n
If you are interested in contributing to s2n, please see our [development guide](https://github.com/awslabs/s2n/blob/master/docs/DEVELOPMENT-GUIDE.md).
