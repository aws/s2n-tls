#pragma once

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#define verify S2N_KYBER_512_R3_NAMESPACE(verify)
int verify(const uint8_t *a, const uint8_t *b, size_t len);

#define cmov S2N_KYBER_512_R3_NAMESPACE(cmov)
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);
