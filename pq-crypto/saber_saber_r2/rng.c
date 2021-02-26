//
//  rng.c
//
// modified from original source to just single function
// and leverage s2n native implementation

#include <string.h>
#include "rng.h"
#include "pq-crypto/s2n_pq_random.h"

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength)
{
}

int
randombytes(unsigned char *x, unsigned long long xlen)
{

    if (s2n_result_is_ok(s2n_get_random_bytes((uint8_t*) x, (uint32_t) xlen)) )
    	return RNG_SUCCESS;
    else
	return RNG_BAD_MAXLEN;
}


