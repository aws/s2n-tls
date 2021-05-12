/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#if defined(S2N_BIKE_R3_VPCLMUL)

#include "gf2x_internal.h"

#define AVX512_INTERNAL
#include "x86_64_intrinsic.h"

#define CLMUL(x, y, imm) _mm512_clmulepi64_epi128((x), (y), (imm))

_INLINE_ void
mul2_512(OUT __m512i *h, OUT __m512i *l, IN const __m512i a, IN const __m512i b)
{
  const __m512i mask_abq = SET_I64(6, 7, 4, 5, 2, 3, 0, 1);
  const __m512i s1       = a ^ PERMX_I64(a, _MM_SHUFFLE(2, 3, 0, 1));
  const __m512i s2       = b ^ PERMX_I64(b, _MM_SHUFFLE(2, 3, 0, 1));

  __m512i lq  = CLMUL(a, b, 0x00);
  __m512i hq  = CLMUL(a, b, 0x11);
  __m512i abq = lq ^ hq ^ CLMUL(s1, s2, 0x00);
  abq         = PERMXVAR_I64(mask_abq, abq);
  *l          = MXOR_I64(lq, 0xaa, lq, abq);
  *h          = MXOR_I64(hq, 0x55, hq, abq);
}

// 8x8 Karatsuba multiplication
_INLINE_ void gf2x_mul8_512_int(OUT __m512i *zh,
                                OUT __m512i *    zl,
                                IN const __m512i a,
                                IN const __m512i b)
{
  const __m512i mask0   = SET_I64(13, 12, 5, 4, 9, 8, 1, 0);
  const __m512i mask1   = SET_I64(15, 14, 7, 6, 11, 10, 3, 2);
  const __m512i mask2   = SET_I64(3, 2, 1, 0, 7, 6, 5, 4);
  const __m512i mask3   = SET_I64(11, 10, 9, 8, 3, 2, 1, 0);
  const __m512i mask4   = SET_I64(15, 14, 13, 12, 7, 6, 5, 4);
  const __m512i mask_s1 = SET_I64(7, 6, 5, 4, 1, 0, 3, 2);
  const __m512i mask_s2 = SET_I64(3, 2, 7, 6, 5, 4, 1, 0);

  __m512i xl, xh, xabl, xabh, xab, xab1, xab2;
  __m512i yl, yh, yabl, yabh, yab;
  __m512i t[4];

  // Calculate:
  // AX1^AX3|| AX2^AX3 || AX0^AX2 || AX0^AX1
  // BX1^BX3|| BX2^BX3 || BX0^BX2 || BX0^BX1
  // Where (AX1^AX3 || AX0^AX2) stands for (AX1 || AX0)^(AX3 || AX2) = AY0^AY1
  t[0] = PERMXVAR_I64(mask_s1, a) ^ PERMXVAR_I64(mask_s2, a);
  t[1] = PERMXVAR_I64(mask_s1, b) ^ PERMXVAR_I64(mask_s2, b);

  // Calculate:
  // Don't care || AX1^AX3^AX0^AX2
  // Don't care || BX1^BX3^BX0^BX2
  t[2] = t[0] ^ VALIGN(t[0], t[0], 4);
  t[3] = t[1] ^ VALIGN(t[1], t[1], 4);

  mul2_512(&xh, &xl, a, b);
  mul2_512(&xabh, &xabl, t[0], t[1]);
  mul2_512(&yabh, &yabl, t[2], t[3]);

  xab  = xl ^ xh ^ PERMX2VAR_I64(xabl, mask0, xabh);
  yl   = PERMX2VAR_I64(xl, mask3, xh);
  yh   = PERMX2VAR_I64(xl, mask4, xh);
  xab1 = VALIGN(xab, xab, 6);
  xab2 = VALIGN(xab, xab, 2);
  yl   = MXOR_I64(yl, 0x3c, yl, xab1);
  yh   = MXOR_I64(yh, 0x3c, yh, xab2);

  __m512i oxh = PERMX2VAR_I64(xabl, mask1, xabh);
  __m512i oxl = VALIGN(oxh, oxh, 4);
  yab         = oxl ^ oxh ^ PERMX2VAR_I64(yabl, mask0, yabh);
  yab         = MXOR_I64(oxh, 0x3c, oxh, VALIGN(yab, yab, 2));
  yab ^= yl ^ yh;

  // Z0 (yl) + Z1 (yab) + Z2 (yh)
  yab = PERMXVAR_I64(mask2, yab);
  *zl = MXOR_I64(yl, 0xf0, yl, yab);
  *zh = MXOR_I64(yh, 0x0f, yh, yab);
}

// 1024x1024 bit multiplication performed by Karatsuba algorithm.
// Here, a and b are considered as having 16 digits of size 64 bits.
void gf2x_mul_base_vpclmul(OUT uint64_t *c,
                           IN const uint64_t *a,
                           IN const uint64_t *b)
{
  const __m512i a0 = LOAD(a);
  const __m512i a1 = LOAD(&a[QWORDS_IN_ZMM]);
  const __m512i b0 = LOAD(b);
  const __m512i b1 = LOAD(&b[QWORDS_IN_ZMM]);

  __m512i hi[2], lo[2], mi[2];

  gf2x_mul8_512_int(&lo[1], &lo[0], a0, b0);
  gf2x_mul8_512_int(&hi[1], &hi[0], a1, b1);
  gf2x_mul8_512_int(&mi[1], &mi[0], a0 ^ a1, b0 ^ b1);

  __m512i m = lo[1] ^ hi[0];

  STORE(&c[0 * QWORDS_IN_ZMM], lo[0]);
  STORE(&c[1 * QWORDS_IN_ZMM], mi[0] ^ lo[0] ^ m);
  STORE(&c[2 * QWORDS_IN_ZMM], mi[1] ^ hi[1] ^ m);
  STORE(&c[3 * QWORDS_IN_ZMM], hi[1]);
}

void gf2x_sqr_vpclmul(OUT dbl_pad_r_t *c, IN const pad_r_t *a)
{
  __m512i va, vm, vr0, vr1;

  const uint64_t *a64 = (const uint64_t *)a;
  uint64_t *      c64 = (uint64_t *)c;

  vm = SET_I64(7, 3, 6, 2, 5, 1, 4, 0);

  for(size_t i = 0; i < (R_ZMM * QWORDS_IN_ZMM); i += QWORDS_IN_ZMM) {
    va = LOAD(&a64[i]);
    va = PERMXVAR_I64(vm, va);

    vr0 = CLMUL(va, va, 0x00);
    vr1 = CLMUL(va, va, 0x11);

    STORE(&c64[i * 2], vr0);
    STORE(&c64[i * 2 + QWORDS_IN_ZMM], vr1);
  }
}

#endif

typedef int dummy_typedef_to_avoid_empty_translation_unit_warning;
