#ifndef VERIFY_H
#define VERIFY_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#define verify S2N_KYBER_512_R3_NAMESPACE(_verify)
int verify(const uint8_t *a, const uint8_t *b, size_t len);

#define cmov S2N_KYBER_512_R3_NAMESPACE(_cmov)
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

#endif
