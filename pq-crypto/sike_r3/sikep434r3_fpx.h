/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: core functions over GF(p) and GF(p^2)
*********************************************************************************************/

#pragma once

#include <string.h>
#include "sikep434r3.h"
#include "sikep434r3_fp.h"

#define fp2_encode S2N_SIKE_P434_R3_NAMESPACE(fp2_encode)
void fp2_encode(const f2elm_t *x, unsigned char *enc);

#define fp2_decode S2N_SIKE_P434_R3_NAMESPACE(fp2_decode)
void fp2_decode(const unsigned char *x, f2elm_t *dec);

#define copy_words S2N_SIKE_P434_R3_NAMESPACE(copy_words)
void copy_words(const digit_t* a, digit_t* c, const unsigned int nwords);

#define fp2copy S2N_SIKE_P434_R3_NAMESPACE(fp2copy)
void fp2copy(const f2elm_t *a, f2elm_t *c);

#define fp2div2 S2N_SIKE_P434_R3_NAMESPACE(fp2div2)
void fp2div2(const f2elm_t *a, f2elm_t *c);

#define mp_add S2N_SIKE_P434_R3_NAMESPACE(mp_add)
unsigned int mp_add(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords);

#define fp2sqr_mont S2N_SIKE_P434_R3_NAMESPACE(fp2sqr_mont)
void fp2sqr_mont(const f2elm_t *a, f2elm_t *c);

#define fp2mul_mont S2N_SIKE_P434_R3_NAMESPACE(fp2mul_mont)
void fp2mul_mont(const f2elm_t *a, const f2elm_t *b, f2elm_t *c);

#define fp2inv_mont S2N_SIKE_P434_R3_NAMESPACE(fp2inv_mont)
void fp2inv_mont(f2elm_t *a);

#define mp_shiftr1 S2N_SIKE_P434_R3_NAMESPACE(mp_shiftr1)
void mp_shiftr1(digit_t* x, const unsigned int nwords);

#define decode_to_digits S2N_SIKE_P434_R3_NAMESPACE(decode_to_digits)
void decode_to_digits(const unsigned char* x, digit_t* dec, int nbytes, int ndigits);

#define fpcopy S2N_SIKE_P434_R3_NAMESPACE(fpcopy)
void fpcopy(const felm_t a, felm_t c);

#define fpzero S2N_SIKE_P434_R3_NAMESPACE(fpzero)
void fpzero(felm_t a);

#define fp2add S2N_SIKE_P434_R3_NAMESPACE(fp2add)
void fp2add(const f2elm_t *a, const f2elm_t *b, f2elm_t *c);

#define fp2sub S2N_SIKE_P434_R3_NAMESPACE(fp2sub)
void fp2sub(const f2elm_t *a, const f2elm_t *b, f2elm_t *c);

#define mp_addfast S2N_SIKE_P434_R3_NAMESPACE(mp_addfast)
void mp_addfast(const digit_t* a, const digit_t* b, digit_t* c);

#define mp2_add S2N_SIKE_P434_R3_NAMESPACE(mp2_add)
void mp2_add(const f2elm_t *a, const f2elm_t *b, f2elm_t *c);

#define mp2_sub_p2 S2N_SIKE_P434_R3_NAMESPACE(mp2_sub_p2)
void mp2_sub_p2(const f2elm_t *a, const f2elm_t *b, f2elm_t *c);
