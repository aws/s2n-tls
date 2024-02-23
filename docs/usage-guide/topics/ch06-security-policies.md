# Security Policies

s2n-tls uses pre-made security policies to help avoid common misconfiguration mistakes for TLS.

`s2n_config_set_cipher_preferences()` sets a security policy, which includes the cipher/kem/signature/ecc preferences and protocol version.

## Supported TLS Versions

Currently TLS 1.2 is our default version, but we recommend TLS 1.3 where possible. To use TLS 1.3 you need a security policy that supports TLS 1.3.
**Note:** s2n-tls does not support SSL2.0 for sending and receiving encrypted data, but does accept SSL2.0 hello messages.

### Chart: Security Policy Version To Protocol Version And Ciphersuites

The following chart maps the security policy version to protocol version and ciphersuites supported.

|    version    | TLS1.0 | TLS1.1 | TLS1.2 | TLS1.3 | AES-CBC | AES-GCM | CHACHAPOLY | 3DES | RC4 | DHE | ECDHE | RSA kx |
|---------------|--------|--------|--------|--------|---------|---------|------------|------|-----|-----|-------|--------|
|   20230317    |        |        |    X   |    X   |    X    |    X    |            |      |     |     |   X   |        |
|    default    |    X   |    X   |    X   |        |    X    |    X    |      X     |      |     |     |   X   |    X   |
| default_tls13 |    X   |    X   |    X   |    X   |    X    |    X    |      X     |      |     |     |   X   |    X   |
| default_fips  |        |        |    X   |        |    X    |    X    |            |      |     |  X  |   X   |        |
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

The "default", "default_tls13", and "default_fips" versions are special in that they will be updated with future s2n-tls changes and ciphersuites and protocol versions may be added and removed, or their internal order of preference might change. Numbered versions are fixed and will never change.
In general, customers prefer to use numbered versions for production use cases to prevent impact from library updates.

"20230317" is a FIPS compliant policy. It offers more limited but more secure options than "default". It only supports TLS1.2 and TLS1.3. Consider this policy if you plan to enable FIPS mode or don't need or want to support less secure legacy options like TLS1.1 or SHA1.

"20160411" follows the same general preference order as "default". The main difference is it has a CBC cipher suite at the top. This is to accommodate certain Java clients that have poor GCM implementations. Users of s2n-tls who have found GCM to be hurting performance for their clients should consider this version.

"rfc9151" is derived from [Commercial National Security Algorithm (CNSA) Suite Profile for TLS and DTLS 1.2 and 1.3](https://datatracker.ietf.org/doc/html/rfc9151). This policy restricts the algorithms allowed for signatures on certificates in the certificate chain to RSA or ECDSA with sha384, which may require you to update your certificates.

s2n-tls does not expose an API to control the order of preference for each ciphersuite or protocol version. s2n-tls follows the following order:

*NOTE*: All ChaCha20-Poly1305 cipher suites will not be available if s2n-tls is not built with an Openssl 1.1.1 libcrypto. The underlying encrypt/decrypt functions are not available in older versions.

1. Always prefer the highest protocol version supported
2. Always use forward secrecy where possible. Prefer ECDHE over DHE.
3. Prefer encryption ciphers in the following order: AES128, AES256, ChaCha20, 3DES, RC4.
4. Prefer record authentication modes in the following order: GCM, Poly1305, SHA256, SHA1, MD5.

#### ChaCha20 Boosting

s2n-tls usually prefers AES over ChaCha20. However, some clients-- particularly mobile or IOT devices-- do not support AES hardware acceleration, making AES less efficient and performant than ChaCha20. In this case, clients will indicate their preference for ChaCha20 by listing it first during cipher suite negotiation. Usually s2n-tls servers ignore client preferences, but s2n-tls offers "ChaCha20 boosted" security policies that will choose ChaCha20 over AES if the client indicates a preference for ChaCha20. This is available in the "CloudFront-TLS-1-2-2021-ChaCha20-Boosted" policy, which is identical to the "CloudFront-TLS-1-2-2021" policy listed above but with ChaCha20 Boosting enabled.

### Chart: Security Policy Version To Supported Signature Schemes

|    version    | RSA PKCS1 | ECDSA | SHA-1 Legacy | RSA PSS |
|---------------|-----------|-------|--------------|---------|
|   20230317    |     X     |   X   |              |    X    |
|    default    |     X     |       |       X      |         |
| default_tls13 |     X     |   X   |       X      |    X    |
| default_fips  |     X     |   X   |              |         |
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

Note that legacy SHA-1 algorithms are not supported in TLS1.3. Legacy SHA-1 algorithms will be supported only if TLS1.2 has been negotiated and the security policy allows them.

### Chart: Security policy version to supported curves/groups

|    version    | secp256r1 | secp384r1 | x25519 |
|---------------|-----------|-----------|--------|
|   20230317    |     X     |     X     |        |
|    default    |     X     |     X     |        |
| default_tls13 |     X     |     X     |    X   |
| default_fips  |     X     |     X     |        |
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

### Certificate Preferences

The security policy struct contains three fields related to certificate preferences. These function differently from the other security policy fields because they are not sent to the peer as part of negotiation. Instead they are a set of rules that the endpoint will enforce locally.

`certificate_signature_preferences` determine which certificate signatures are allowed in certificates. This field is an allowlist of `(signature_algorithm, digest)` tuples. Allowed `signature_algorithm`s are ECDSA, RSA PKCS v1.5, and RSA PSS. Note that s2n-tls does not currently provide support for restricting the digest types of RSA PSS signature, so a security policy using certificate signature preferences must either allow all digests with RSA PSS signatures or disallow RSA PSS signatures entirely.

`certificate_key_preferences` determine which key types are allowed in certificates. This field is an allowlist of `(key type, size)` tuples, where key type is the OID (Object Identifier) contained in the cert. Allowed RSA key types are `rsaEncryption` and `rsassaPSS` with 1024, 2048, 3072, and 4096 bit moduli. Allowed EC key types are `prime256v1`, `secp384r1`, and `secp521r1` with their respective sizes. 

Certificates received from a peer are validated after they have been parsed, but before any cryptographic verification has been done. These certificates will be validated even if they aren't used in the construction of the final cert chain. Note that certificate signature preferences are not enforced on self signed certs, because the signature of a self signed cert does not affect the security of the certificate chain.

Certificates in a trust store are only validated when are used to build a chain. For example, if the security policy certificate key preferences only allows 3096 bit RSA certs, the config could still load a system trust store that contains 2048 bit certs. However no connections will actually be able to use the non-compliant 2048 bit RSA certs, and they will be effectively untrusted by s2n-tls.

Certificates loaded into a config are only validated if the `certificate_preferences_apply_locally` field in the security policy is true. Validation happens when `s2n_connection_set_config` is called, or when `s2n_connection_set_cipher_preferences` is used to set a connection override. If the certificate loaded into the config are not permitted by the certificate preferences, then `s2n_connection_set_config` will fail. Note that certificate signature preferences are enforced on all certs loaded into the config, even if they are self signed.
