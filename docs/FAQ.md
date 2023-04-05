# FAQ for s2n-tls

## Why is the ClientHello version reported as TLS 1.2 but the handshake itself negotiated TLS 1.3?
The TLS 1.3 spec uses the TLS 1.2 version in ClientHello and on record layers for compatibility with middleboxes and poor server implementations. There is a separate ClientHello extension which lists the actual versions supported.

## Why is my TLS handshake failing on validating my peer’s certificate? I gave my s2n endpoint a root certificate that verifies the peer’s certificate.
You may need to validate the peer’s hostname by implementing the s2n_verify_host_fn callback. The default behavior may need to be altered for your usecase.

## Why is s2n hanging for so long before erroring?
s2n-tls sleeps for 10-30 seconds after specific errors occur to prevent peers from learning about encrypted data. This technique is called blinding and it is utilized to prevent side-channel attacks.

## When does `s2n_connection_get_handshake_type_name()` include the WITH_SESSION_TICKET flag in a TLS12 handshake, but not in a TLS13 handshake? Is the TLS13 handshake still doing session resumption?
In TLS13 the session ticket is sent after the handshake in a post-handshake message. Since the handshake itself no longer contains this message, the `s2n_connection_get_handshake_type_name()` will not include it.

## Which security policy should I use if I want to make sure that it will never be altered?
Our numbered security policies are guaranteed to never change. We will not alter or update them based on changing cryptography standards. However, our named security policies (like “default” or “default_tls13”) change based on new cryptography standards that come out. 

## Does s2n-tls have an OpenSSL compatibility layer to make transitioning to s2n-tls easier? 
s2n-tls does not provide compatibility with OpenSSL’s APIs. OpenSSL’s APIs are complex and creating a shim layer would take a lot of engineering effort. Currently we would rather focus on making our library as easy to use as possible and building useful features.

## s2n-tls isn’t compiling on x platform/architecture/compiler version. Can you fix the issue?
Please open an issue if you notice a compile issue on a specific platform or compiler version. Keep in mind that we usually cannot merge a fix for a specific compile issue unless that build is already running in our CI. This is because we cannot verify that the fix worked if the build is not already running in our CI. Submitting an issue will give us a signal that we need to start supporting a specific build in our CI that we currently do not.
