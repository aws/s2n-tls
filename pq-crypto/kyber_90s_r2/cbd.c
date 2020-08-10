#include "cbd.h"
#include "params.h"

#include <stddef.h>
#include <stdint.h>

/*************************************************
* Name:        load32_littleendian
*
* Description: load bytes into a 32-bit integer
*              in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x
**************************************************/
static uint32_t load32_littleendian(const uint8_t *x) {
    uint32_t r;
    r  = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    r |= (uint32_t)x[3] << 24;
    return r;
}

/*************************************************
* Name:        cbd
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter KYBER_ETA
*              specialized for KYBER_ETA=2
*
* Arguments:   - poly *r:                  pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
void PQCLEAN_KYBER51290S_CLEAN_cbd(poly *r, const uint8_t *buf) {
    uint32_t d, t;
    int16_t a, b;

    for (size_t i = 0; i < KYBER_N / 8; i++) {
        t = load32_littleendian(buf + 4 * i);
        d  = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (size_t j = 0; j < 8; j++) {
            a = (d >>  4 * j)      & 0x3;
            b = (d >> (4 * j + 2)) & 0x3;
            r->coeffs[8 * i + j] = a - b;
        }
    }
}
