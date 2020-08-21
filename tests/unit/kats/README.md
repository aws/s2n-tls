# Known Answer Test Files
Known answer tests are used to verify correctness of certain functionality within s2n. The fixed test vectors in the KAT
files are compared against calculated values during unit tests. Currently, all KATs are applicable only to
post-quantum/hybrid functionality.

## NIST KATs
KATs of the form `${KEM}_r${N}.kat` (e.g. `sike_r2.kat`) are provided by NIST as part of their
[post-quantum cryptography standardization effort](https://csrc.nist.gov/projects/post-quantum-cryptography).
These KATs are used to verify that the `generate_keypair`, `encapsulate`, and `decapsulate` functions for each PQ-KEM
are correct. The `seed` value for each test vector is used as entropy to initialize the DRBG during the unit test
so that the test can replicate the deterministic randomness used to generate the `pk`, `sk`, `ct`, and `ss` values.
All values are represented as hex-encoded strings.

All NIST KATs were generated with a DRBG in AES 256 counter mode, no derivation function, no prediction resistance.

## Hybrid KATs
KATs of the form `hybrid_echde_${KEM}_r${N}.kat` (e.g. `hybrid_echde_sike_r2.kat`) are used to verify that client and
server are correctly generating, parsing, and processing the server key exchange message, client key exchange message,
and master secret for hybrid TLS 1.2. The `seed` value for each test vector is used as entropy to initialize the DRBG
during the unit test so that the test can replicate the deterministic randomness used to generate the ECDHE keys,
PQ-KEM keys, shared secrets, and ciphertexts used to construct the key fixed exchange messages. The values for
`expected_server_key_exchange` and `expected_client_key_exchange` are hex-encoded bytes, exactly as they would appear
over the wire during a TLS 1.2 handshake (the `Record Header` and `Handshake Header` bytes are omitted).

All hybrid KAT test vectors were generated with a DRBG in AES 256 counter mode, no derivation function
(`S2N_AES_256_CTR_NO_DF_PR`). `secp256r1` is used as the ECDHE curve for each KAT.

## Hybrid PRF KAT
The `hybrid_prf.kat` KAT is used to verify correctness of the TLS 1.2 hybrid PRF responsible for deriving the master
secret. The test vectors were generated from an independent implementation of the hybrid PRF. The values
`premaster_kem_secret_length` and `client_key_exchange_message_length` must be defined in the KAT file, since they vary
based on the PQ-KEM. The length must be specified as a base 10 integer. The lengths for all other elements do not vary
and are defined in the source test files. The values for `premaster_classic_secret`, `premaster_kem_secret`,
`client_random`, `server_random`, `client_key_exchange_message`, and `master_secret` are represented as hex-encoded
strings.
