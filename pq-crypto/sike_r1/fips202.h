#ifndef FIPS202_H
#define FIPS202_H

#include <stdint.h>


#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

void cshake256_simple_absorb(uint64_t *s, uint16_t cstm, const unsigned char *in, unsigned long long inlen);
void cshake256_simple(unsigned char *output, unsigned long long outlen, uint16_t cstm, const unsigned char *in, unsigned long long inlen);

#endif
