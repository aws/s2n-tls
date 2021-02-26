#include <string.h>
#include <stdint.h>
#include "SABER_indcpa.h"
#include "poly.h"
#include "pack_unpack.h"
#include "poly_mul.c"
#include "rng.h"
#include "fips202.h"
#include "SABER_params.h"

#define h1 (1 << (SABER_EQ - SABER_EP - 1))
#define h2 ((1 << (SABER_EP - 2)) - (1 << (SABER_EP - SABER_ET - 1)) + (1 << (SABER_EQ - SABER_EP - 1)))

void indcpa_kem_keypair(uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], uint8_t sk[SABER_INDCPA_SECRETKEYBYTES])
{
	uint16_t A[SABER_L][SABER_L][SABER_N];
	uint16_t s[SABER_L][SABER_N];
	uint16_t b[SABER_L][SABER_N] = {0};

	uint8_t seed_A[SABER_SEEDBYTES];
	uint8_t seed_s[SABER_NOISE_SEEDBYTES];
	int i, j;

	randombytes(seed_A, SABER_SEEDBYTES);
	shake128(seed_A, SABER_SEEDBYTES, seed_A, SABER_SEEDBYTES); // for not revealing system RNG state
	randombytes(seed_s, SABER_NOISE_SEEDBYTES);

	GenMatrix(A, seed_A);
	GenSecret(s, seed_s);
	MatrixVectorMul(A, s, b, 1);

	for (i = 0; i < SABER_L; i++)
	{
		for (j = 0; j < SABER_N; j++)
		{
			b[i][j] = (b[i][j] + h1) >> (SABER_EQ - SABER_EP);
		}
	}

	POLVECq2BS(sk, s);
	POLVECp2BS(pk, b);
	memcpy(pk + SABER_POLYVECCOMPRESSEDBYTES, seed_A, sizeof(seed_A));
}

void indcpa_kem_enc(uint8_t m[SABER_KEYBYTES], uint8_t seed_sp[SABER_NOISE_SEEDBYTES], const uint8_t pk[SABER_INDCPA_PUBLICKEYBYTES], uint8_t ciphertext[SABER_BYTES_CCA_DEC])
{
	uint16_t A[SABER_L][SABER_L][SABER_N];
	uint16_t sp[SABER_L][SABER_N];
	uint16_t bp[SABER_L][SABER_N] = {0};
	uint16_t vp[SABER_N] = {0};
	uint16_t mp[SABER_N];
	uint16_t b[SABER_L][SABER_N];
	int i, j;
	const uint8_t *seed_A = pk + SABER_POLYVECCOMPRESSEDBYTES;

	GenMatrix(A, seed_A);
	GenSecret(sp, seed_sp);
	MatrixVectorMul(A, sp, bp, 0);

	for (i = 0; i < SABER_L; i++)
	{
		for (j = 0; j < SABER_N; j++)
		{
			bp[i][j] = (bp[i][j] + h1) >> (SABER_EQ - SABER_EP);
		}
	}

	POLVECp2BS(ciphertext, bp);
	BS2POLVECp(pk, b);
	InnerProd(b, sp, vp);

	BS2POLmsg(m, mp);

	for (j = 0; j < SABER_N; j++)
	{
		vp[j] = (vp[j] - (mp[j] << (SABER_EP - 1)) + h1) >> (SABER_EP - SABER_ET);
	}

	POLT2BS(ciphertext + SABER_POLYVECCOMPRESSEDBYTES, vp);
}

void indcpa_kem_dec(const uint8_t sk[SABER_INDCPA_SECRETKEYBYTES], const uint8_t ciphertext[SABER_BYTES_CCA_DEC], uint8_t m[SABER_KEYBYTES])
{

	uint16_t s[SABER_L][SABER_N];
	uint16_t b[SABER_L][SABER_N];
	uint16_t v[SABER_N] = {0};
	uint16_t cm[SABER_N];
	int i;

	BS2POLVECq(sk, s);
	BS2POLVECp(ciphertext, b);
	InnerProd(b, s, v);
	BS2POLT(ciphertext + SABER_POLYVECCOMPRESSEDBYTES, cm);

	for (i = 0; i < SABER_N; i++)
	{
		v[i] = (v[i] + h2 - (cm[i] << (SABER_EP - SABER_ET))) >> (SABER_EP - 1);
	}

	POLmsg2BS(m, v);
}
