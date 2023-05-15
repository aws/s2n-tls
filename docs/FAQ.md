# FAQ for s2n-tls

### Why is my connection using TLS1.0?
It is possible that your security policy allows TLS1.0 and your peer only
supports TLS1.0. However, if you're reading the version "TLS1.0" from a packet
capture, make sure that you're reading the right version field. The TLS protocol
includes several legacy version fields that have ossified, making it difficult
to understand what version was negotiated.

For backwards compatibility reasons, the version field in the TLS record header
is set to "TLS1.0" when sending the ClientHello message, and for later messages
is still never set higher than "TLS1.2".
The ClientHello message has its own version field, which will also never be set
higher than "TLS1.2" for similar reasons.
If the client does support TLS1.3, it will include that information in the ClientHello
"supported_versions" extension instead of setting any of the legacy version fields.

s2n-tls offers [methods](USAGE-GUIDE/#protocol-version) to retrieve accurate protocol versions.

### Why isn't my connection using TLS1.3?
There are several possible reasons:
* Are you using a security policy that supports TLS1.3? See [security policies](USAGE-GUIDE.md/#security-policies).
* Are you verifying the connection version correctly? See [the previous question](FAQ.md#why-is-my-connection-using-tls10).
* Are you using a libcrypto library that supports TLS1.3? Modern libcrypto libraries support the algorithms needed for TLS1.3, but older libraries like Openssl 1.0.2 do not. If s2n-tls is built with Openssl 1.0.2, TLS1.3 is unlikely to be negotiated. 
* Does your peer support TLS1.3? If your peer does not support TLS1.3, TLS1.3 will not be negotiated.

### Why is the TLS handshake failing on validating my peer's certificate?
Have you already configure a trust store to be able to trust your peer's certificate? If so it may be necessary to implement `s2n_verify_host_fn` as the default behavior may not work for your use case. See the [certificates](USAGE-GUIDE.md/#certificates-and-authentication) section for detailed instructions on verifying a peer's certificate.

### Why is s2n hanging for so long before erroring?
s2n-tls sleeps for a random period between 10 and 30 seconds after specific errors occur to avoid leaking any secret information via timing data. This technique is called blinding and it is utilized to prevent timing side-channel attacks. See [blinding](USAGE-GUIDE.md/#blinding).

### Which security policy should I use if I want to make sure that it will never be altered?
Our numbered security policies are guaranteed to never change. We will not alter or update them based on changing cryptography standards. However, our named security policies (like “default” or “default_tls13”) change based on new cryptography standards that come out. See [security policies](USAGE-GUIDE.md/#security-policies).

### Why does s2n-tls have a dependency on OpenSSL? Isn't s2n-tls a replacement for OpenSSL?
OpenSSL includes both a TLS library, called libssl, and a cryptography library, called libcrypto. s2n-tls implements a TLS library, but does not implement a cryptography library. Instead, s2n-tls links to a separate libcrypto in order to perform cryptographic operations. Libcryptos other than OpenSSL can be used, such as [AWS-LC](https://github.com/aws/aws-lc).

### Does s2n-tls have an OpenSSL compatibility layer to make transitioning to s2n-tls easier? 
s2n-tls does not provide compatibility with OpenSSL’s APIs. OpenSSL’s APIs are complex and creating a shim layer would take a lot of engineering effort. Currently we are focused on making our library as easy to use as possible and building useful features. A better choice for API compatibility with OpenSSL is [AWS-LC](https://github.com/aws/aws-lc).

### s2n-tls isn’t compiling on x platform/architecture/compiler version. Can you fix the issue?
Please open an issue if you notice a compile issue on a specific platform or compiler version. Keep in mind that we usually cannot merge a fix for a specific compile issue unless that build is already running in our CI. This is because we cannot verify that the fix worked if the build is not already running in our CI. Submitting an issue will give us a signal that we need to start supporting a specific build in our CI that we currently do not.
