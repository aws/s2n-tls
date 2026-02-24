# Post Quantum (PQ) Support

s2n-tls supports both post-quantum key exchange and post-quantum authentication for TLS1.3.

## Key Exchange: ML-KEM

Currently, only [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) is supported for post-quantum key exchange.

Specifically, s2n-tls supports hybrid key exchange. PQ hybrid key exchange involves performing both classic ECDH key exchange and post-quantum key exchange, then combining the two resultant secrets. This strategy combines the high assurance of the classical key exchange algorithms with the quantum-resistance of the new post-quantum key exchange algorithms. If one of the two algorithms is compromised, either because advances in quantum computing make the classic algorithms insecure or because cryptographers find a flaw in the relatively new post-quantum algorithms, the secret is still secure. Hybrid post-quantum key exchange is more secure than standard key exchange, but is slower and requires more processing and more network bandwidth.

Careful: An s2n-tls server that enables post-quantum cryptography will mandate post-quantum key exchange with any client advertising post-quantum algorithms. This can result in a retry and an extra round trip if the client does not initially send a post-quantum key share. The rational behind this behavior is that post-quantum users prioritize security over the potential cost of an extra round trip.

## Authentication: ML-DSA

Currently, only [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) is supported for post-quantum authentication.

In order to use ML-DSA, you must configure s2n-tls to use an ML-DSA certificate, just as you would configure an RSA or ECDSA certificate. See [certificates](./ch09-certificates.md).

## Requirements

### AWS-LC

s2n-tls must be built with aws-lc to use post-quantum algorithms. See the [s2n-tls build documentation](https://github.com/aws/s2n-tls/blob/main/docs/BUILD.md#building-with-a-specific-libcrypto) for how to build with aws-lc. For ML-DSA, you will need to use a version of AWS-LC >= v1.50.0 (API version 33).

If you're unsure what cryptography library s2n-tls is built against, trying running s2nd or s2nc:
```
> s2nd localhost 8000
libcrypto: AWS-LC
Listening on localhost:8000
```

### Security Policy

Post-quantum algorithms are enabled by configuring a security policy (see [Security Policies](./ch06-security-policies.md)) that supports post-quantum algorithms. 

"default_pq" is the equivalent of "default_tls13", but with PQ support. Like the other default policies, "default_pq" may change as a result of library updates. The fixed, numbered equivalent of "default_pq" is currently "20250721". For previous defaults, see the "Default Policy History" section below.

"cnsa2" is derived from [Commercial National Security Algorithm (CNSA) Suite Profile for TLS 1.3](https://datatracker.ietf.org/doc/draft-becker-cnsa2-tls-profile/). This is a TLS 1.3 PQ only policy that requires pure ML-KEM-1024 for key exchange and ML-DSA-87 for signature and certificate verification.

"cnsa_1_2_hybrid" is a transitional policy from CNSA 1.0 / RFC 9151 (non-PQ) to CNSA 2.0 (PQ only). It combines all the supported algorithms in the "cnsa2" and "rfc9151" (see [Security Policies](./ch06-security-policies.md)) policies. Like other default policies, these CNSA policies are subject to the source RFC definition changes.

Other available PQ policies are compared in the tables below.

### Chart: Security Policy Version To PQ Key Exchange Methods (ML-KEM)

|        Version        | x25519+mlkem768 | secp256r1+mlkem768 | secp384r1+mlkem1024 | mlkem1024 |
|-----------------------|-----------------|--------------------|---------------------|-----------|
| default_pq / 20250721 |        X        |          X         |          X          |           |
| 20250512              |        X        |          X         |                     |           |
| cnsa2                 |                 |                    |                     |     X     |
| cnsa_1_2_hybrid       |                 |                    |                     |     X     |

### Chart: Security Policy Version To Signature Schemes

|        Version        | ML-DSA | ECDSA | RSA | RSA-PSS | Legacy SHA1 |
|-----------------------|--------|-------|-----|---------|-------------|
| default_pq / 20250721 |   X    |   X   |  X  |    X    |             |
| 20250512              |   X    |   X   |  X  |    X    |             |
| cnsa2                 |   87   |       |     |         |             |
| cnsa_1_2_hybrid       |   87   |   X   |  X  |    X    |             |

### Chart: Security Policy Version To Classic Key Exchange

If the peer doesn't support a PQ hybrid key exchange method, s2n-tls will fall back to a classical option.

Note: the "cnsa2" policy only allows ML-KEM-1024, thus there is no fallback to classic key exchange.

|        Version        | secp256r1 | x25519 | secp384r1 | secp521r1 | DHE | RSA |
|-----------------------|-----------|--------|-----------|-----------|-----|-----|
| default_pq / 20250721 |     X     |   X    |     X     |     X     |     |     |
| 20250512              |     X     |   X    |     X     |     X     |     |     |
| cnsa_1_2_hybrid       |           |        |     X     |           |     |     |

### Chart: Security Policy Version To Ciphers

|        Version        | AES-CBC | AES-GCM | CHACHAPOLY | 3DES |
|-----------------------|---------|---------|------------|------|
| default_pq / 20250721 |    X    |    X    |     X      |      |
| 20250512              |    X    |    X    |     X      |      |
| cnsa2                 |         |    X    |            |      |
| cnsa_1_2_hybrid       |         |    X    |            |      |

### Chart: Security Policy Version To TLS Protocol Version

|        Version        | 1.2 | 1.3 |
|-----------------------|-----|-----|
| default_pq / 20250721 |  X  |  X  |
| 20250512              |  X  |  X  |
| cnsa2                 |     |  X  |
| cnsa_1_2_hybrid       |  X  |  X  |

#### Default Policy History
|  Version   | "default_pq" |
|------------|--------------|
|  v1.5.23   |   20250721   |
|  v1.5.19   |   20250512   |
|  v1.5.6    |   20241001   |
|  v1.5.0    |   20240730   |

## Visibility
Call `s2n_connection_get_kem_group_name` to determine if a TLS handshake negotiated PQ key exchange.