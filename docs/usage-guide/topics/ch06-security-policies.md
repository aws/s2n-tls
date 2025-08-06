# Security Policies

s2n-tls uses pre-made security policies to help avoid common misconfiguration mistakes for TLS.

`s2n_config_set_cipher_preferences()` sets a security policy, which includes the cipher/kem/signature/ecc preferences and protocol version.

## Supported TLS Versions

Currently TLS 1.2 is our default version, but we recommend TLS 1.3 where possible. To use TLS 1.3 you need a security policy that supports TLS 1.3.

## Deprecation of Security Policies

s2n-tls may deprecate security policies. If s2n-tls drops support for an algorithm included in a security policy, the behavior of the security policy might unexpectedly change. Because s2n-tls promises that versioned policies will never change, we instead deprecate affected security policies. If a security policy is deprecated, users will receive a `S2N_ERR_DEPRECATED_SECURITY_POLICY` usage error when requesting that policy.
### SSL 3.0, TLS 1.0, and TLS 1.1
s2n-tls supports older versions, but their use is not recommended.

Compatibility with older versions of TLS may also require support for older ciphersuites. Although it is possible to negotiate older versions of TLS with more modern options like SHA256, AES, ECDSA, and ECDHE, older clients and servers may only support older options like SHA1, 3DES, RSA certs, and either RSA or DHE key exchange. If a security policy allows older TLS versions but does not allow older ciphersuites, handshakes with older clients and servers may fail.

### SSL 2.0
s2n-tls will not negotiate SSL 2.0, but will accept SSLv2 ClientHellos advertising a higher protocol version like TLS1.2. See the ["Compatibility with SSL 2.0"](https://datatracker.ietf.org/doc/html/rfc5246#appendix-E.2) section in the TLS 1.2 RFC.

Compatibility with SSLv2 ClientHellos advertising TLS1.2 may require similar support for older ciphersuites as compatibility with older versions of TLS does. In particular, SSLv2 ClientHellos are likely to require support for SHA1 and either RSA or DHE key exchange. This is due to technical limitations of the SSLv2 ClientHello, which does not include TLS extensions.

### Chart: Security Policy Version To Protocol Version And Ciphersuites

The following chart maps the security policy version to protocol version and ciphersuites supported.

|    version    | TLS1.0 | TLS1.1 | TLS1.2 | TLS1.3 | AES-CBC | AES-GCM | CHACHAPOLY | 3DES | RC4 | DHE | ECDHE | RSA kx |
|---------------|--------|--------|--------|--------|---------|---------|------------|------|-----|-----|-------|--------|
|    default    |        |        |    X   |        |    X    |    X    |            |      |     |     |   X   |        |
| default_fips  |        |        |    X   |        |    X    |    X    |            |      |     |     |   X   |        |
| default_tls13 |        |        |    X   |    X   |    X    |    X    |      X     |      |     |     |   X   |        |
|   20240501    |        |        |    X   |        |    X    |    X    |            |      |     |     |   X   |        |
|   20240502    |        |        |    X   |        |    X    |    X    |            |      |     |     |   X   |        |
|   20240503    |        |        |    X   |    X   |    X    |    X    |            |      |     |     |   X   |        |
|   20230317    |        |        |    X   |    X   |    X    |    X    |            |      |     |     |   X   |        |
|   20240331    |        |        |    X   |        |    X    |    X    |            |      |     |     |   X   |        |
|   20190214    |    X   |    X   |    X   |        |    X    |    X    |            |   X  |     |  X  |   X   |    X   |
|   20170718    |    X   |    X   |    X   |        |    X    |    X    |            |      |     |     |   X   |    X   |
|   20170405    |    X   |    X   |    X   |        |    X    |    X    |            |   X  |     |     |   X   |    X   |
|   20170328    |    X   |    X   |    X   |        |    X    |    X    |            |   X  |     |  X  |   X   |    X   |
|   20170210    |    X   |    X   |    X   |        |    X    |    X    |      X     |      |     |     |   X   |    X   |
|   20160824    |    X   |    X   |    X   |        |    X    |    X    |            |      |     |     |   X   |    X   |
|   20160804    |    X   |    X   |    X   |        |    X    |    X    |            |   X  |     |     |   X   |    X   |
|   20160411    |    X   |    X   |    X   |        |    X    |    X    |            |   X  |     |     |   X   |    X   |
|   20150306    |    X   |    X   |    X   |        |    X    |    X    |            |   X  |     |     |   X   |    X   |
|   20150214    |    X   |    X   |    X   |        |    X    |    X    |            |   X  |     |  X  |       |    X   |
|   20150202    |    X   |    X   |    X   |        |    X    |         |            |   X  |     |  X  |       |    X   |
|   20141001    |    X   |    X   |    X   |        |    X    |         |            |   X  |  X  |  X  |       |    X   |
|   20190120    |    X   |    X   |    X   |        |    X    |    X    |      X     |   X  |     |     |   X   |    X   |
|   20190121    |    X   |    X   |    X   |        |    X    |    X    |      X     |   X  |     |     |   X   |    X   |
|   20190122    |    X   |    X   |    X   |        |    X    |    X    |      X     |   X  |     |     |   X   |    X   |
|   20190801    |    X   |    X   |    X   |    X   |    X    |    X    |      X     |      |     |     |   X   |    X   |
|   20190802    |    X   |    X   |    X   |    X   |    X    |    X    |      X     |      |     |     |   X   |    X   |
|   20200207    |        |        |        |    X   |         |    X    |      X     |      |     |     |   X   |        |
|    rfc9151    |        |        |    X   |    X   |         |    X    |            |      |     |  X  |   X   |    X   |

The "default", "default_tls13", and "default_fips" versions are special in that they will be updated with future s2n-tls changes to keep up-to-date with current security best practices. Ciphersuites, protocol versions, and other options may be added or removed, or their internal order of preference might change. **Warning**: this means that the default policies may change as a result of library updates, which could break peers that rely on legacy options.

In contrast, numbered or dated versions are fixed and will never change.

The numbered equivalents for the named policies for the current version and
historical s2n versions are in the "Named Policy History" below. The current
matching fixed versions are:

| "default" | "default_fips" | "default_tls13" | "rfc9151" |
|-----------|----------------|-----------------|-----------|
| 20240501  |   20240502     |    20240503     |  20250429 |

"default_fips" does not currently support TLS1.3. If you need a policy that supports both FIPS and TLS1.3, choose "20230317". We plan to add TLS1.3 support to both "default" and "default_fips" in the future.

"rfc9151" is derived from [Commercial National Security Algorithm (CNSA) Suite Profile for TLS and DTLS 1.2 and 1.3](https://datatracker.ietf.org/doc/html/rfc9151). This policy restricts the algorithms allowed for signatures on certificates in the certificate chain to RSA or ECDSA with sha384, which may require you to update your certificates.
Like the default policies, this policy may also change if the source RFC definition changes.

s2n-tls does not expose an API to control the order of preference for each ciphersuite or protocol version. s2n-tls follows the following order:

1. Always prefer the highest protocol version supported
2. Always use forward secrecy where possible. Prefer ECDHE over DHE.
3. Prefer encryption ciphers in the following order: AES128, AES256, ChaCha20, 3DES, RC4.
4. Prefer record authentication modes in the following order: GCM, Poly1305, SHA256, SHA1, MD5.

*NOTE*: ChaCha20-Poly1305 cipher suites will not be available if s2n-tls is built with an older libcrypto like openssl-1.0.2. The underlying encrypt/decrypt functions are not available in older versions.

#### ChaCha20 Boosting

s2n-tls usually prefers AES over ChaCha20. However, some clients-- particularly mobile or IOT devices-- do not support AES hardware acceleration, making AES less efficient and performant than ChaCha20. In this case, clients will indicate their preference for ChaCha20 by listing it first during cipher suite negotiation. Usually s2n-tls servers ignore client preferences, but s2n-tls offers "ChaCha20 boosted" security policies that will choose ChaCha20 over AES if the client indicates a preference for ChaCha20. This is available in the "CloudFront-TLS-1-2-2021-ChaCha20-Boosted" policy, which is identical to the "CloudFront-TLS-1-2-2021" policy listed above but with ChaCha20 Boosting enabled.

### Chart: Security Policy Version To Supported Signature Schemes

|    version    | RSA PKCS1 | ECDSA | SHA-1 Legacy | RSA PSS |
|---------------|-----------|-------|--------------|---------|
|    default    |     X     |   X   |              |    X    |
| default_fips  |     X     |   X   |              |    X    |
| default_tls13 |     X     |   X   |              |    X    |
|   20240501    |     X     |   X   |              |    X    |
|   20240502    |     X     |   X   |              |    X    |
|   20240503    |     X     |   X   |              |    X    |
|   20230317    |     X     |   X   |              |    X    |
|   20190214    |     X     |   X   |       X      |         |
|   20170718    |     X     |       |       X      |         |
|   20170405    |     X     |       |       X      |         |
|   20170328    |     X     |       |       X      |         |
|   20170210    |     X     |       |       X      |         |
|   20160824    |     X     |       |       X      |         |
|   20160804    |     X     |       |       X      |         |
|   20160411    |     X     |       |       X      |         |
|   20150306    |     X     |       |       X      |         |
|   20150214    |     X     |       |       X      |         |
|   20150202    |     X     |       |       X      |         |
|   20141001    |     X     |       |       X      |         |
|   20190120    |     X     |       |       X      |         |
|   20190121    |     X     |       |       X      |         |
|   20190122    |     X     |       |       X      |         |
|   20190801    |     X     |   X   |       X      |    X    |
|   20190802    |     X     |   X   |       X      |    X    |
|   20200207    |           |   X   |              |    X    |
|    rfc9151    |     X     |   X   |              |    X    |

*NOTE*: Legacy SHA-1 algorithms are not supported in TLS1.3. Legacy SHA-1 algorithms will be supported only if TLS1.2 has been negotiated and the security policy allows them.

*NOTE*: RSA-PSS certificates will not be available if s2n-tls is built with an older libcrypto like openssl-1.0.2. RSA certificate signatures with PSS padding (RSA-PSS-RSAE) will still be available, but RSA-PSS certificate signatures with PSS padding (RSA-PSS-PSS) will not be available.

### Chart: Security policy version to supported curves/groups

|    version    | secp256r1 | secp384r1 | x25519 |
|---------------|-----------|-----------|--------|
|    default    |     X     |     X     |    X   |
| default_fips  |     X     |     X     |        |
| default_tls13 |     X     |     X     |    X   |
|   20240501    |     X     |     X     |    X   |
|   20240502    |     X     |     X     |        |
|   20240503    |     X     |     X     |    X   |
|   20230317    |     X     |     X     |        |
|   20190214    |     X     |     X     |        |
|   20170718    |     X     |     X     |        |
|   20170405    |     X     |     X     |        |
|   20170328    |     X     |     X     |        |
|   20170210    |     X     |     X     |        |
|   20160824    |     X     |     X     |        |
|   20160804    |     X     |     X     |        |
|   20160411    |     X     |     X     |        |
|   20150306    |     X     |     X     |        |
|   20150214    |           |           |        |
|   20150202    |           |           |        |
|   20141001    |           |           |        |
|   20190120    |     X     |     X     |        |
|   20190121    |     X     |     X     |        |
|   20190122    |     X     |     X     |        |
|   20190801    |     X     |     X     |    X   |
|   20190802    |     X     |     X     |        |
|   20200207    |     X     |     X     |    X   |
|    rfc9151    |           |     X     |        |

### Named Policy History

|  Version   | "default" | "default_fips" | "default_tls13" | "rfc9151" |
|------------|-----------|----------------|-----------------|-----------|
|  v1.5.25   | 20240501  |   20240502     |    20240503     |  20250429 |
|  v1.4.16   | 20240501  |   20240502     |    20240503     |    (*)    |
|   Older    | 20170210  |   20240416     |    20240417     |    (*)    |

(*): No fixed policy available.
