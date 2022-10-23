#include <stdint.h>
#include "kyber512r3_params.h"
#include "kyber512r3_cbd.h"

S2N_ENSURE_PORTABLE_OPTIMIZATIONS

/*************************************************
* Name:        load32_littleendian
*
* Description: load 4 bytes into a 32-bit integer
*              in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x
**************************************************/
static uint32_t load32_littleendian(const uint8_t x[4]) {
    uint32_t r;
    r  = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    r |= (uint32_t)x[3] << 24;
    return r;
}

/*************************************************
* Name:        load24_littleendian
*
* Description: load 3 bytes into a 32-bit integer
*              in little-endian order
*              This function is only needed for Kyber-512
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
**************************************************/
static uint32_t load24_littleendian(const uint8_t x[3]) {
    uint32_t r;
    r  = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    return r;
}


/*************************************************
* Name:        cbd2
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=2
*
* Arguments:   - poly *r:            pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
static void cbd2(poly *r, const uint8_t buf[2 * S2N_KYBER_512_R3_N / 4]) {
    unsigned int i, j;

    for (i = 0; i < S2N_KYBER_512_R3_N / 8; i++) {
        uint32_t t  = load32_littleendian(buf + 4 * i);
        uint32_t d  = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (j = 0; j < 8; j++) {
            int16_t a = (d >> (4 * j + 0)) & 0x3;
            int16_t b = (d >> (4 * j + 2)) & 0x3;
            r->coeffs[8 * i + j] = a - b;
        }
    }
}

/*************************************************
* Name:        cbd3
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=3
*              This function is only needed for Kyber-512
*
* Arguments:   - poly *r:            pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
static void cbd3(poly *r, const uint8_t buf[3 * S2N_KYBER_512_R3_N / 4]) {
    unsigned int i, j;

    for (i = 0; i < S2N_KYBER_512_R3_N / 4; i++) {
        uint32_t t  = load24_littleendian(buf + 3 * i);
        uint32_t d  = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for (j = 0; j < 4; j++) {
            int16_t a = (d >> (6 * j + 0)) & 0x7;
            int16_t b = (d >> (6 * j + 3)) & 0x7;
            r->coeffs[4 * i + j] = a - b;
        }
    }
}

void cbd_eta1(poly *r, const uint8_t buf[S2N_KYBER_512_R3_ETA1 * S2N_KYBER_512_R3_N / 4]) {
    cbd3(r, buf);
}

void cbd_eta2(poly *r, const uint8_t buf[S2N_KYBER_512_R3_ETA2 * S2N_KYBER_512_R3_N / 4]) {
    cbd2(r, buf);
}
