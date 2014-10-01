Amazon s2n (pronounced “stun”) is an implementation of the TLS/SSL protocols.
It is designed for servers, and supports SSLv3, TLS1.0, TLS1.1 and TLS1.2. s2n
is released and licensed under the Apache Software License version 2. 

s2n includes several features designed to enhance the security and versatility
of applications:

* **Systematic C safety** s2n is written in C, but makes light use of standard C library functions and wraps all buffer handling and serialization in boundary-enforcing checks. 
* **Erase on read** s2n’s copies of decrypted data buffers are erased as they are read by the application. 
* **No locking overhead** There are no mutexes or locks in s2n. 
* **Small code base** Ignoring tests, blank lines and comments, s2n is about 3,000 lines of code. 
* **Minimalist feature adoption** s2n targets servers and aims to satisfy the common use cases, while avoiding little used features. Additionally; features with a history of triggering protocol-level vulnerabilities are not implemented. For example there is no support for session renegotiation or DTLS. 
* **Table based state-machines** s2n uses simple tables to drive the TLS/SSL state machines, making it difficult for invalid out-of-order states to arise. 
* **Built-in memory protection** On Linux; data buffers may not be swapped to disk or appear in core dumps.

s2n uses OpenSSL’s libcrypto for the underlying cryptographic operations.
Cryptographic routines have been written in a modular way so that it is also
possible to use BoringSSL, LibreSSL or other cryptographic libraries for these
operations. 

s2n handles the protocol validation, state machine and buffer handling, while
encryption and decryption are handled by passing simple and opaque data “blobs”
to the cryptographic libraries for processing.  

At this time, s2n has support for the AES256-CBC, AES128-CBC, 3DES-CBC and RC4
ciphers, and the RSA and DHE-RSA (a form of perfect forward secrecy) key
exchange algorithms.  For more detail about s2n, see the [API Reference],
[Example server], and [Backlog].

Security and vulnerability notifications AWS s2n has been subject to internal
Amazon code review and an external security review.  Security is an ongoing
process and reviews are not a certification that s2n is defect free. 

If you discover a security vulnerability or issue in s2n we ask that you notify
it to AWS Security via our vulnerability reporting page. 
