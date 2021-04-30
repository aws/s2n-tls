#pragma once

/* All kyber512r3 functions and global variables in the pq-crypto/kyber_r3 directory
 * should be defined using the namespace macro to avoid symbol collisions. For example,
 * in foo.h, declare a function as follows:
 *
 * #define foo_function S2N_KYBER_512_R3_NAMESPACE(foo_function)
 * int foo_function(int foo_argument); */
#define S2N_KYBER_512_R3_NAMESPACE(s) s2n_kyber_512_r3_##s

#define S2N_KYBER_512_R3_K 2

#define S2N_KYBER_512_R3_N 256
#define S2N_KYBER_512_R3_Q 3329

#define S2N_KYBER_512_R3_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define S2N_KYBER_512_R3_SSBYTES  32   /* size in bytes of shared key */

#define S2N_KYBER_512_R3_POLYBYTES     384
#define S2N_KYBER_512_R3_POLYVECBYTES  (S2N_KYBER_512_R3_K * S2N_KYBER_512_R3_POLYBYTES)

#define S2N_KYBER_512_R3_ETA1 3
#define S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES    128
#define S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES 640

#define S2N_KYBER_512_R3_ETA2 2

#define S2N_KYBER_512_R3_INDCPA_MSGBYTES       S2N_KYBER_512_R3_SYMBYTES
#define S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES (S2N_KYBER_512_R3_POLYVECBYTES + S2N_KYBER_512_R3_SYMBYTES)
#define S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES (S2N_KYBER_512_R3_POLYVECBYTES)
#define S2N_KYBER_512_R3_INDCPA_BYTES          (S2N_KYBER_512_R3_POLYVECCOMPRESSEDBYTES + S2N_KYBER_512_R3_POLYCOMPRESSEDBYTES)
