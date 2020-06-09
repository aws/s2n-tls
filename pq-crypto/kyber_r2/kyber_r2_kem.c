// SPDX-License-Identifier: MIT

#include <stdlib.h>
#include <stdint.h>

#include "kem_kyber.h"
#include "params.h"
#include "indcpa.h"
#include "symmetric.h"
#include "verify.h"
#include "../pq_random.h"
#include "utils/s2n_safety.h"


//#include "rand.h"
//#include "randombytes.h"
//#include "fips202.h"

/*
 #include "api.h"

 #include "randombytes.h"
 #include "symmetric.h"
 #include "verify.h"
 */

#include <stdlib.h>

//pqclean_kyber512_clean

//OQS_KEM *OQS_KEM_kyber_512_new() {
//
//	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
//	if (kem == NULL) {
//		return NULL;
//	}
//	kem->method_name = OQS_KEM_alg_kyber_512;
//	kem->alg_version = "https://github.com/pq-crystals/kyber/commit/46e283ab575ec92dfe82fb12229ae2d9d6246682";
//
//	kem->claimed_nist_level = 1;
//	kem->ind_cca = true;
//
//	kem->length_public_key = OQS_KEM_kyber_512_length_public_key;
//	kem->length_secret_key = OQS_KEM_kyber_512_length_secret_key;
//	kem->length_ciphertext = OQS_KEM_kyber_512_length_ciphertext;
//	kem->length_shared_secret = OQS_KEM_kyber_512_length_shared_secret;
//
//	kem->keypair = OQS_KEM_kyber_512_keypair;
//	kem->encaps = OQS_KEM_kyber_512_encaps;
//	kem->decaps = OQS_KEM_kyber_512_decaps;
//
//	return kem;
//}

int PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
	size_t i;
	PQCLEAN_KYBER512_CLEAN_indcpa_keypair(pk, sk);
	for (i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++) {
		sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
	}
	hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk,
			KYBER_PUBLICKEYBYTES);
	GUARD_AS_POSIX(get_random_bytes(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES));
	//randombytes(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES); /* Value z for pseudo-random output on reject */
	return 0;
}

int PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss,
		const uint8_t *pk) {
	unsigned char kr[2 * KYBER_SYMBYTES]; /* Will contain key, coins */
	unsigned char buf[2 * KYBER_SYMBYTES];

	GUARD_AS_POSIX(get_random_bytes(buf, KYBER_SYMBYTES));
	//randombytes(buf, KYBER_SYMBYTES);
	hash_h(buf, buf, KYBER_SYMBYTES); /* Don't release system RNG output */

	hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES); /* Multitarget countermeasure for coins + contributory KEM */
	hash_g(kr, buf, 2 * KYBER_SYMBYTES);

	PQCLEAN_KYBER512_CLEAN_indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES); /* coins are in kr+KYBER_SYMBYTES */

	hash_h(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES); /* overwrite coins in kr with H(c) */
	kdf(ss, kr, 2 * KYBER_SYMBYTES); /* hash concatenation of pre-k and H(c) to k */
	return 0;
}

int PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct,
		const uint8_t *sk) {
	size_t i;
	unsigned char fail;
	unsigned char cmp[KYBER_CIPHERTEXTBYTES];
	unsigned char buf[2 * KYBER_SYMBYTES];
	unsigned char kr[2 * KYBER_SYMBYTES]; /* Will contain key, coins */
	const unsigned char *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

	PQCLEAN_KYBER512_CLEAN_indcpa_dec(buf, ct, sk);

	for (i = 0; i < KYBER_SYMBYTES; i++) { /* Multitarget countermeasure for coins + contributory KEM */
		buf[KYBER_SYMBYTES + i] = sk[KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES
				+ i]; /* Save hash by storing H(pk) in sk */
	}
	hash_g(kr, buf, 2 * KYBER_SYMBYTES);

	PQCLEAN_KYBER512_CLEAN_indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES); /* coins are in kr+KYBER_SYMBYTES */

	fail = PQCLEAN_KYBER512_CLEAN_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

	hash_h(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES); /* overwrite coins in kr with H(c)  */

	PQCLEAN_KYBER512_CLEAN_cmov(kr, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
			KYBER_SYMBYTES, fail); /* Overwrite pre-k with z on re-encryption failure */

	kdf(ss, kr, 2 * KYBER_SYMBYTES); /* hash concatenation of pre-k and H(c) to k */
	return 0;
}

