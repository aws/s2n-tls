/*-------------------------------------------------
This file has been adapted from the implementation 
(available at https://github.com/pq-crystals/kyber) of 
"CRYSTALS – Kyber: a CCA-secure module-lattice-based KEM"
 by : Joppe Bos, Leo Ducas, Eike Kiltz, Tancrede Lepoint, 
Vadim Lyubashevsky, John M. Schanck, Peter Schwabe & Damien stehle
----------------------------------------------------*/
#ifndef VERIFY_H
#define VERIFY_H

#include <stdio.h>

/* returns 0 for equal strings, 1 for non-equal strings */
int verify(const unsigned char *a, const unsigned char *b, size_t len);

/* b = 1 means mov, b = 0 means don't mov*/
void cmov(unsigned char *r, const unsigned char *x, size_t len, unsigned char b);

#endif
