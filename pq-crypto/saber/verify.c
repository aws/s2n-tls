/*-------------------------------------------------
This file has been adapted from the implementation 
(available at https://github.com/pq-crystals/kyber) of 
"CRYSTALS – Kyber: a CCA-secure module-lattice-based KEM"
 by : Joppe Bos, Leo Ducas, Eike Kiltz, Tancrede Lepoint, 
Vadim Lyubashevsky, John M. Schanck, Peter Schwabe & Damien stehle
----------------------------------------------------*/
#include <string.h>
#include <stdint.h>
#include "verify.h"

/* returns 0 for equal strings, 1 for non-equal strings */
int verify(const unsigned char *a, const unsigned char *b, size_t len)
{
  uint64_t r;
  size_t i;
  r = 0;

  for (i = 0; i < len; i++)
    r |= a[i] ^ b[i];

  r = (-r) >> 63;
  return r;
}

/* b = 1 means mov, b = 0 means don't mov*/
void cmov(unsigned char *r, const unsigned char *x, size_t len, unsigned char b)
{
  size_t i;

  b = -b;
  for (i = 0; i < len; i++)
    r[i] ^= b & (x[i] ^ r[i]);
}
