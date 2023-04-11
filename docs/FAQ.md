# FAQ for s2n-tls

### Why isn't my connection using TLS1.3?
There are several reasons why the TLS protocol version may not be what you expected. One is that the TLS protocol has some legacy version fields that have ossified, making it more difficult to understand what protocol was negotiated. The TLS1.3 protocol sets the ClientHello version to TLS1.2 for backwards compatibility with poorly implemented TLS servers and middleboxes. The record version is set to TLS 1.1 in the ClientHello for the same reason. There is a separate ClientHello extension called "supported_versions" which lists the actual versions supported, included TLS1.3. See the [protocol version section](USAGE-GUIDE/#protocol-version) to check the real protocol negotiated.
Additionally you need a security policy that supports TLS1.3 in order to negotiate TLS1.3. See [security policies](USAGE-GUIDE.md/#security-policies).

### Why is the TLS handshake failing on validating my peer's certificate?
Have you already configure a trust store to be able to trust your peer's certificate? If so it may be necessary to implement `s2n_verify_host_fn` as the default behavior may not work for your use case. See the [certificates](USAGE-GUIDE.md/#certificates-and-authentication) section for detailed instructions on verifying a peer's certificate.

### Why is s2n hanging for so long before erroring?
s2n-tls sleeps for a random period between 10 and 30 seconds after specific errors occur to prevent peers from learning about encrypted data. This technique is called blinding and it is utilized to prevent side-channel attacks. See [blinding](USAGE-GUIDE.md/#blinding).

### Which security policy should I use if I want to make sure that it will never be altered?
Our numbered security policies are guaranteed to never change. We will not alter or update them based on changing cryptography standards. However, our named security policies (like “default” or “default_tls13”) change based on new cryptography standards that come out. See [security policies](USAGE-GUIDE.md/#security-policies).

### Why does s2n-tls have a dependency on OpenSSL? Isn't s2n-tls a replacement for OpenSSL?
s2n-tls links to a libcrypto in order to perform cryptographic operations. OpenSSL is a well-known libcrypto library that can provide those cryptographic operations, but other libcryptos can be used as well, such as [AWS-LC](https://github.com/aws/aws-lc).

### Does s2n-tls have an OpenSSL compatibility layer to make transitioning to s2n-tls easier? 
s2n-tls does not provide compatibility with OpenSSL’s APIs. OpenSSL’s APIs are complex and creating a shim layer would take a lot of engineering effort. Currently we are focused on making our library as easy to use as possible and building useful features. A better choice for API compatibility with OpenSSL is [AWS-LC](https://github.com/aws/aws-lc).

### s2n-tls isn’t compiling on x platform/architecture/compiler version. Can you fix the issue?
Please open an issue if you notice a compile issue on a specific platform or compiler version. Keep in mind that we usually cannot merge a fix for a specific compile issue unless that build is already running in our CI. This is because we cannot verify that the fix worked if the build is not already running in our CI. Submitting an issue will give us a signal that we need to start supporting a specific build in our CI that we currently do not.
