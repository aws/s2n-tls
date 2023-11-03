+++
title = 'Security policies'
date = 2023-10-04T17:54:48-07:00
draft = false
weight = 61
+++

s2n-tls uses pre-made security policies to help avoid common misconfiguration mistakes for TLS.

`s2n_config_set_cipher_preferences()` sets a security policy, which includes the cipher/kem/signature/ecc preferences and protocol version.

## Chart: Security policy version to protocol version and ciphersuites

The following chart maps the security policy version to protocol version and ciphersuites supported.

|          version          | SSLv3 | TLS1.0 | TLS1.1 | TLS1.2 | TLS1.3  | AES-CBC | AES-GCM | ChaCha20-Poly1305 | 3DES | RC4 | DHE | ECDHE |
|---------------------------|-------|--------|--------|--------|---------|---------|---------|-------------------|------|-----|-----|-------|
|         "default"         |       |   X    |    X   |    X   |         |    X    |    X    |                   |      |     |     |   X   |
|       "default_tls13"     |       |   X    |    X   |    X   |    X    |    X    |    X    |          X        |      |     |     |   X   |
|       "default_fips"      |       |        |        |    X   |         |    X    |    X    |                   |      |     |  X  |   X   |
|         "20190214"        |       |   X    |    X   |    X   |         |    X    |    X    |                   |  X   |     |  X  |   X   |
|         "20170718"        |       |   X    |    X   |    X   |         |    X    |    X    |                   |      |     |     |   X   |
|         "20170405"        |       |   X    |    X   |    X   |         |    X    |    X    |                   |  X   |     |     |   X   |
|         "20170328"        |       |   X    |    X   |    X   |         |    X    |    X    |                   |  X   |     |  X  |   X   |
|         "20170210"        |       |   X    |    X   |    X   |         |    X    |    X    |          X        |      |     |     |   X   |
|         "20160824"        |       |   X    |    X   |    X   |         |    X    |    X    |                   |      |     |     |   X   |
|         "20160804"        |       |   X    |    X   |    X   |         |    X    |    X    |                   |  X   |     |     |   X   |
|         "20160411"        |       |   X    |    X   |    X   |         |    X    |    X    |                   |  X   |     |     |   X   |
|         "20150306"        |       |   X    |    X   |    X   |         |    X    |    X    |                   |  X   |     |     |   X   |
|         "20150214"        |       |   X    |    X   |    X   |         |    X    |    X    |                   |  X   |     |  X  |       |
|         "20150202"        |       |   X    |    X   |    X   |         |    X    |         |                   |  X   |     |  X  |       |
|         "20141001"        |       |   X    |    X   |    X   |         |    X    |         |                   |  X   |  X  |  X  |       |
|         "20140601"        |   X   |   X    |    X   |    X   |         |    X    |         |                   |  X   |  X  |  X  |       |
|         "20190120"        |       |   X    |    X   |    X   |         |    X    |    X    |                   |  X   |     |     |   X   |
|         "20190121"        |       |   X    |    X   |    X   |         |    X    |    X    |                   |  X   |     |     |   X   |
|         "20190122"        |       |   X    |    X   |    X   |         |    X    |    X    |                   |  X   |     |  X  |   X   |
|         "20190801"        |       |   X    |    X   |    X   |    X    |    X    |    X    |          X        |      |     |     |   X   |
|         "20190802"        |       |   X    |    X   |    X   |    X    |    X    |    X    |          X        |      |     |     |   X   |
|         "20200207"        |       |   X    |    X   |    X   |    X    |    X    |    X    |          X        |      |     |     |       |
|         "20230317"        |       |        |        |    X   |    X    |    X    |    X    |                   |      |     |     |   X   |
|         "rfc9151"         |       |        |        |    X   |    X    |         |    X    |                   |      |     |  X  |   X   |
| "CloudFront-TLS-1-2-2021" |       |        |        |    X   |    X    |         |    X    |          X        |      |     |     |   X   |

The "default", "default_tls13", and "default_fips" versions are special in that they will be updated with future s2n-tls changes and ciphersuites and protocol versions may be added and removed, or their internal order of preference might change. Numbered versions are fixed and will never change.
In general, customers prefer to use numbered versions for production use cases to prevent impact from library updates.

"20230317" offers more limited but more secure options than "default". It only supports TLS1.2 and TLS1.3 and is FIPS compliant. Choose this policy if you don't need or want to support less secure legacy options like TLS1.1 or SHA1.

"20160411" follows the same general preference order as "default". The main difference is it has a CBC cipher suite at the top. This is to accommodate certain Java clients that have poor GCM implementations. Users of s2n-tls who have found GCM to be hurting performance for their clients should consider this version.

"20170405" is a FIPS compliant cipher suite preference list based on approved algorithms in the [FIPS 140-2 Annex A](http://csrc.nist.gov/publications/fips/fips140-2/fips1402annexa.pdf). Similarly to "20160411", this preference list has CBC cipher suites at the top to accommodate certain Java clients. Users of s2n-tls who plan to enable FIPS mode should consider this version.

"rfc9151" is derived from [Commercial National Security Algorithm (CNSA) Suite Profile for TLS and DTLS 1.2 and 1.3](https://datatracker.ietf.org/doc/html/rfc9151). This policy restricts the algorithms allowed for signatures on certificates in the certificate chain to RSA or ECDSA with sha384, which may require you to update your certificates.

s2n-tls does not expose an API to control the order of preference for each ciphersuite or protocol version. s2n-tls follows the following order:

*NOTE*: All ChaCha20-Poly1305 cipher suites will not be available if s2n-tls is not built with an Openssl 1.1.1 libcrypto. The underlying encrypt/decrypt functions are not available in older versions.

1. Always prefer the highest protocol version supported
2. Always use forward secrecy where possible. Prefer ECDHE over DHE.
3. Prefer encryption ciphers in the following order: AES128, AES256, ChaCha20, 3DES, RC4.
4. Prefer record authentication modes in the following order: GCM, Poly1305, SHA256, SHA1, MD5.

### ChaCha20 boosting

s2n-tls usually prefers AES over ChaCha20. However, some clients-- particularly mobile or IOT devices-- do not support AES hardware acceleration, making AES less efficient and performant than ChaCha20. In this case, clients will indicate their preference for ChaCha20 by listing it first during cipher suite negotiation. Usually s2n-tls servers ignore client preferences, but s2n-tls offers "ChaCha20 boosted" security policies that will choose ChaCha20 over AES if the client indicates a preference for ChaCha20. This is available in the "CloudFront-TLS-1-2-2021-ChaCha20-Boosted" policy, which is identical to the "CloudFront-TLS-1-2-2021" policy listed above but with ChaCha20 Boosting enabled.

## Chart: Security policy version to supported signature schemes

|    version     |   RSA PKCS1  |   ECDSA  |  SHA-1 Legacy |  RSA PSS |
|----------------|--------------|----------|---------------|----------|
|   "default"    |      X       |     X    |      X        |          |
| "default_tls13"|      X       |     X    |      X        |    X     |
| "default_fips" |      X       |     X    |               |          |
|   "20190214"   |      X       |     X    |      X        |          |
|   "20170718"   |      X       |     X    |      X        |          |
|   "20170405"   |      X       |     X    |      X        |          |
|   "20170328"   |      X       |     X    |      X        |          |
|   "20170210"   |      X       |     X    |      X        |          |
|   "20160824"   |      X       |     X    |      X        |          |
|   "20160804"   |      X       |     X    |      X        |          |
|   "20160411"   |      X       |     X    |      X        |          |
|   "20150306"   |      X       |     X    |      X        |          |
|   "20150214"   |      X       |     X    |      X        |          |
|   "20150202"   |      X       |     X    |      X        |          |
|   "20141001"   |      X       |     X    |      X        |          |
|   "20140601"   |      X       |     X    |      X        |          |
|   "20190120"   |      X       |     X    |      X        |          |
|   "20190121"   |      X       |     X    |      X        |          |
|   "20190122"   |      X       |     X    |      X        |          |
|   "20190801"   |      X       |     X    |      X        |    X     |
|   "20190802"   |      X       |     X    |      X        |    X     |
|   "20200207"   |      X       |     X    |      X        |    X     |
|   "20230317"   |      X       |     X    |               |    X     |
|   "rfc9151"    |      X       |     X    |               |    X     |

Note that the default_tls13 security policy will never support legacy SHA-1 algorithms in TLS1.3, but will support
legacy SHA-1 algorithms in CertificateVerify messages if TLS1.2 has been negotiated.

## Chart: Security policy version to supported curves/groups

|    version     |   secp256r1  |  secp384r1 | x25519 |
|----------------|--------------|------------|--------|
|   "default"    |      X       |      X     |        |
| "default_tls13"|      X       |      X     |   X    |
| "default_fips" |      X       |      X     |        |
|   "20190214"   |      X       |      X     |        |
|   "20170718"   |      X       |      X     |        |
|   "20170405"   |      X       |      X     |        |
|   "20170328"   |      X       |      X     |        |
|   "20170210"   |      X       |      X     |        |
|   "20160824"   |      X       |      X     |        |
|   "20160804"   |      X       |      X     |        |
|   "20160411"   |      X       |      X     |        |
|   "20150306"   |      X       |      X     |        |
|   "20150214"   |      X       |      X     |        |
|   "20150202"   |      X       |      X     |        |
|   "20141001"   |      X       |      X     |        |
|   "20140601"   |      X       |      X     |        |
|   "20190120"   |      X       |      X     |        |
|   "20190121"   |      X       |      X     |        |
|   "20190122"   |      X       |      X     |        |
|   "20190801"   |      X       |      X     |   X    |
|   "20190802"   |      X       |      X     |        |
|   "20200207"   |      X       |      X     |   X    |
|   "rfc9151"    |              |      X     |        |
