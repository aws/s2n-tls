# Post-quantum cryptography for s2n
This directory contains code for new post-quantum key exchange mechanisms. There are no known computationally feasible
attacks (classical or quantum) against these algorithms when used with the recommended key lengths.

## Quantum computers
Quantum computers use the properties of quantum mechanics to evaluate quantum algorithms. These algorithms can solve some
classically hard (exponential time) problems quickly (polynomial time). Shor's algorithm is one such algorithm which can
factor large integers, thus breaking RSA encryption and digital signature, and another quantum algorithm can solve the
discrete logarithm problem over arbitrary groups thus breaking Diffie–Hellman and elliptic curve Diffie–Hellman key
exchange.

## Post-quantum cryptography
Post-quantum public-key cryptographic algorithms run on a classical computer and are conjectured secure against both
classical and quantum attacks. NIST is in the process of reviewing submissions and standardizing them,
see more info on the [NIST website](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post-Quantum-Cryptography-Standardization).
Until the review and standardization is complete the post-quantum key exchanges in s2n **must not** be used for key
establishment by themselves. Instead they should only be used as part of a hybrid key exchange, which combines a
post-quantum key exchange scheme and a classical key exchange scheme.

## Hybrid key exchange
A hybrid key exchange combines both the high assurance of classical key exchange with the conjectured quantum-resistance
of newly proposed key exchanges. s2n implements the hybrid specification from [this RFC](https://tools.ietf.org/html/draft-campagna-tls-bike-sike-hybrid-01).
See [this s2n issue](https://github.com/awslabs/s2n/issues/904) for more up-to-date information.

## SIKE (Supersingular Isogeny Key Encapsulation)
The code in the pq-crypto/sike directory was taken from the [round 1 nist submission](https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-1/submissions/SIKE.zip).
s2n uses the reference implementation to ensure maximum comparability and ease of review. The known answer tests are
[here](https://github.com/awslabs/s2n/blob/master/tests/unit/s2n_sike_p503_kat_test.c) and use the known answer file
from the SIKEp503 round 1 submission.