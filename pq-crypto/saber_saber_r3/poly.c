#include <stdio.h>
#include "api.h"
#include "poly.h"
#include "poly_mul.h"
#include "pack_unpack.h"
#include "cbd.h"
#include "fips202.h"

void MatrixVectorMul(const uint16_t A[SABER_L][SABER_L][SABER_N], const uint16_t s[SABER_L][SABER_N], uint16_t res[SABER_L][SABER_N], int16_t transpose)
{
	int i, j;
	for (i = 0; i < SABER_L; i++)
	{
		for (j = 0; j < SABER_L; j++)
		{
			if (transpose == 1)
			{
				poly_mul_acc(A[j][i], s[j], res[i]);
			}
			else
			{
				poly_mul_acc(A[i][j], s[j], res[i]);
			}	
		}
	}
}

void InnerProd(const uint16_t b[SABER_L][SABER_N], const uint16_t s[SABER_L][SABER_N], uint16_t res[SABER_N])
{
	int j;
	for (j = 0; j < SABER_L; j++)
	{
		poly_mul_acc(b[j], s[j], res);
	}
}

void GenMatrix(uint16_t A[SABER_L][SABER_L][SABER_N], const uint8_t seed[SABER_SEEDBYTES])
{
	uint8_t buf[SABER_L * SABER_POLYVECBYTES];
	int i;

	shake128(buf, sizeof(buf), seed, SABER_SEEDBYTES);

	for (i = 0; i < SABER_L; i++)
	{
		BS2POLVECq(buf + i * SABER_POLYVECBYTES, A[i]);
	}
}

void GenSecret(uint16_t s[SABER_L][SABER_N], const uint8_t seed[SABER_NOISE_SEEDBYTES])
{
	uint8_t buf[SABER_L * SABER_POLYCOINBYTES];
	size_t i;

	shake128(buf, sizeof(buf), seed, SABER_NOISE_SEEDBYTES);

	for (i = 0; i < SABER_L; i++)
	{
		cbd(s[i], buf + i * SABER_POLYCOINBYTES);
	}
}
