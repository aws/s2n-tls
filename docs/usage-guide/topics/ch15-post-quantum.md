# Post Quantum (PQ) Support

s2n-tls supports post-quantum key exchange for TLS1.3. Currently, only [Kyber](https://pq-crystals.org/kyber/) is supported. See the draft IETF standard: https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design

Specifically, s2n-tls supports hybrid key exchange. PQ hybrid key exchange involves performing both classic ECDH key exchange and post-quantum Kyber key exchange, then combining the two resultant secrets. This strategy combines the high assurance of the classical key exchange algorithms with the quantum-resistance of the new post-quantum key exchange algorithms. If one of the two algorithms is compromised, either because advances in quantum computing make the classic algorithms insecure or because cryptographers find a flaw in the relatively new post-quantum algorithms, the secret is still secure. Hybrid post-quantum key exchange is more secure than standard key exchange, but is slower and requires more processing and more network bandwidth.

Careful: if an s2n-tls server is configured to support post-quantum key exchange, the server will require that any client that advertises support ultimately uses post-quantum key exchange. That will result in a retry and an extra round trip if the client does not intially provide a post-quantum key share.

## Requirements

### AWS-LC

s2n-tls must be built with aws-lc to use post-quantum key exchange. See the [s2n-tls build documentation](https://github.com/aws/s2n-tls/blob/main/docs/BUILD.md#building-with-a-specific-libcrypto) for how to build with aws-lc.

If you're unsure what cryptography library s2n-tls is built against, trying running s2nd or s2nc:
```
> s2nd localhost 8000
libcrypto: AWS-LC
Listening on localhost:8000
```

### Security Policy

Post-quantum key exchange is enabled by configuring a security policy (see [Security Policies](./ch06-security-policies.md)) that supports post-quantum key exchange algorithms. 

"default_pq" is the equivalent of "default_tls13", but with PQ support. Like the other default policies, "default_pq" may change as a result of library updates. The fixed, numbered equivalent of "default_pq" is currently "20240730". For previous defaults, see the "Default Policy History" section below.

Other available PQ policies are compared in the tables below.

### Chart: Security Policy Version To PQ Hybrid Key Exchange Methods

|        Version        | secp256r1+kyber768 | x25519+kyber768 | secp384r1+kyber768 | secp521r1+kyber1024 | secp256r1+kyber512 | x25519+kyber512 | 
|-----------------------|--------------------|-----------------|--------------------|---------------------|--------------------|-----------------|
| default_pq / 20240730 |          X         |         X       |         X          |          X          |         X          |        X        |
| PQ-TLS-1-2-2023-12-15 |          X         |                 |         X          |          X          |         X          |                 |
| PQ-TLS-1-2-2023-12-14 |          X         |                 |         X          |          X          |         X          |                 |
| PQ-TLS-1-2-2023-12-13 |          X         |                 |         X          |          X          |         X          |                 |
| PQ-TLS-1-2-2023-10-10 |          X         |         X       |         X          |          X          |         X          |        X        |
| PQ-TLS-1-2-2023-10-09 |          X         |         X       |         X          |          X          |         X          |        X        |
| PQ-TLS-1-2-2023-10-08 |          X         |         X       |         X          |          X          |         X          |        X        |
| PQ-TLS-1-2-2023-10-07 |          X         |         X       |         X          |          X          |         X          |        X        |
| PQ-TLS-1-3-2023-06-01 |          X         |         X       |         X          |          X          |         X          |        X        |

### Chart: Security Policy Version To Classic Key Exchange

If the peer doesn't support a PQ hybrid key exchange method, s2n-tls will fall back to a classical option.

|        Version        | secp256r1 | x25519 | secp384r1 | secp521r1 | DHE | RSA |
|-----------------------|-----------|--------|-----------|-----------|-----|-----|
| default_pq / 20240730 |     X     |   X    |     X     |     X     |     |     |
| PQ-TLS-1-2-2023-12-15 |     X     |        |     X     |     X     |  X  |     |
| PQ-TLS-1-2-2023-12-14 |     X     |        |     X     |     X     |     |     |
| PQ-TLS-1-2-2023-12-13 |     X     |        |     X     |     X     |     |  X  |
| PQ-TLS-1-2-2023-10-10 |     X     |   X    |     X     |           |  X  |  X  |
| PQ-TLS-1-2-2023-10-09 |     X     |   X    |     X     |           |  X  |     |
| PQ-TLS-1-2-2023-10-08 |     X     |   X    |     X     |           |  X  |  X  |
| PQ-TLS-1-2-2023-10-07 |     X     |   X    |     X     |           |     |  X  |
| PQ-TLS-1-3-2023-06-01 |     X     |        |     X     |     X     |  X  |  X  |

### Chart: Security Policy Version To Ciphers

|        Version        | AES-CBC | AES-GCM | CHACHAPOLY | 3DES |
|-----------------------|---------|---------|------------|------|
| default_pq / 20240730 |    X    |    X    |     X      |      |
| PQ-TLS-1-2-2023-12-15 |    X    |    X    |            |      |
| PQ-TLS-1-2-2023-12-14 |    X    |    X    |            |      |
| PQ-TLS-1-2-2023-12-13 |    X    |    X    |            |      |
| PQ-TLS-1-2-2023-10-10 |    X    |    X    |     X*     |  X   |
| PQ-TLS-1-2-2023-10-09 |    X    |    X    |     X*     |  X   |
| PQ-TLS-1-2-2023-10-08 |    X    |    X    |     X*     |  X   |
| PQ-TLS-1-2-2023-10-07 |    X    |    X    |     X*     |      |
| PQ-TLS-1-3-2023-06-01 |    X    |    X    |     X*     |  X   |
\* only for TLS1.3

### Chart: Security Policy Version To Signature Schemes

|        Version        |  ECDSA  | RSA | RSA-PSS | Legacy SHA1 |
|-----------------------|---------|-----|---------|-------------|
| default_pq / 20240730 |    X    |  X  |    X    |             |
| PQ-TLS-1-2-2023-12-15 |    X    |  X  |    X    |             |
| PQ-TLS-1-2-2023-12-14 |    X    |  X  |    X    |             |
| PQ-TLS-1-2-2023-12-13 |    X    |  X  |    X    |             |
| PQ-TLS-1-2-2023-10-10 |    X    |  X  |    X    |      X      |
| PQ-TLS-1-2-2023-10-09 |    X    |  X  |    X    |      X      |
| PQ-TLS-1-2-2023-10-08 |    X    |  X  |    X    |      X      |
| PQ-TLS-1-2-2023-10-07 |    X    |  X  |    X    |      X      |
| PQ-TLS-1-3-2023-06-01 |    X    |  X  |    X    |      X      |

### Chart: Security Policy Version To TLS Protocol Version

|        Version        | 1.2 | 1.3 |
|-----------------------|-----|-----|
| default_pq / 20240730 |  X  |  X  |
| PQ-TLS-1-2-2023-12-15 |  X  |  X  |
| PQ-TLS-1-2-2023-12-14 |  X  |  X  |
| PQ-TLS-1-2-2023-12-13 |  X  |  X  |
| PQ-TLS-1-2-2023-10-10 |  X  |  X  |
| PQ-TLS-1-2-2023-10-09 |  X  |  X  |
| PQ-TLS-1-2-2023-10-08 |  X  |  X  |
| PQ-TLS-1-2-2023-10-07 |  X  |  X  |
| PQ-TLS-1-3-2023-06-01 |  X  |  X  |

#### Default Policy History
|  Version   | "default_pq" |
|------------|--------------|
|  v1.5.0   |   20240730   |
