/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: modular arithmetic for P434
*********************************************************************************************/

#pragma once

#include "sikep434r3.h"

#define mp_sub434_p2 S2N_SIKE_P434_R3_NAMESPACE(mp_sub434_p2)
void mp_sub434_p2(const digit_t* a, const digit_t* b, digit_t* c);

#define mp_sub434_p4 S2N_SIKE_P434_R3_NAMESPACE(mp_sub434_p4)
void mp_sub434_p4(const digit_t* a, const digit_t* b, digit_t* c);

#define fpadd434 S2N_SIKE_P434_R3_NAMESPACE(fpadd434)
void fpadd434(const digit_t* a, const digit_t* b, digit_t* c);

#define fpsub434 S2N_SIKE_P434_R3_NAMESPACE(fpsub434)
void fpsub434(const digit_t* a, const digit_t* b, digit_t* c);

#define fpneg434 S2N_SIKE_P434_R3_NAMESPACE(fpneg434)
void fpneg434(digit_t* a);

#define fpdiv2_434 S2N_SIKE_P434_R3_NAMESPACE(fpdiv2_434)
void fpdiv2_434(const digit_t* a, digit_t* c);

#define fpcorrection434 S2N_SIKE_P434_R3_NAMESPACE(fpcorrection434)
void fpcorrection434(digit_t* a);

#define digit_x_digit S2N_SIKE_P434_R3_NAMESPACE(digit_x_digit)
void digit_x_digit(const digit_t a, const digit_t b, digit_t* c);

#define mp_mul S2N_SIKE_P434_R3_NAMESPACE(mp_mul)
void mp_mul(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords);

#define rdc_mont S2N_SIKE_P434_R3_NAMESPACE(rdc_mont)
void rdc_mont(digit_t* ma, digit_t* mc);
