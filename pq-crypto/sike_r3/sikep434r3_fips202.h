/********************************************************************************************
* SHA3-derived function SHAKE
*
* Based on the public domain implementation in crypto_hash/keccakc512/simple/
* from http://bench.cr.yp.to/supercop.html by Ronny Van Keer
* and the public domain "TweetFips202" implementation from https://twitter.com/tweetfips202
* by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe
*
* See NIST Special Publication 800-185 for more information:
* http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
*
*********************************************************************************************/

#pragma once

#include <stdint.h>
#include "sikep434r3.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

#define shake256 S2N_SIKE_P434_R3_NAMESPACE(shake256)
void shake256(unsigned char *output, unsigned long long outlen, const unsigned char *input,  unsigned long long inlen);
