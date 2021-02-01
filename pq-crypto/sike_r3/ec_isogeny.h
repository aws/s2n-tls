/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: elliptic curve and isogeny functions
*********************************************************************************************/

#pragma once

#include "sikep434r3.h"

#define xDBL S2N_SIKE_P434_R3_NAMESPACE(xDBL)
void xDBL(const point_proj_t P, point_proj_t Q, const f2elm_t *A24plus, const f2elm_t *C24);

#define xDBLe S2N_SIKE_P434_R3_NAMESPACE(xDBLe)
void xDBLe(const point_proj_t P, point_proj_t Q, const f2elm_t *A24plus, const f2elm_t *C24, const int e);

#define get_4_isog S2N_SIKE_P434_R3_NAMESPACE(get_4_isog)
void get_4_isog(const point_proj_t P, f2elm_t *A24plus, f2elm_t *C24, f2elm_t *coeff);

#define eval_4_isog S2N_SIKE_P434_R3_NAMESPACE(eval_4_isog)
void eval_4_isog(point_proj_t P, f2elm_t* coeff);

#define xTPL S2N_SIKE_P434_R3_NAMESPACE(xTPL)
void xTPL(const point_proj_t P, point_proj_t Q, const f2elm_t *A24minus, const f2elm_t *A24plus);

#define xTPLe S2N_SIKE_P434_R3_NAMESPACE(xTPLe)
void xTPLe(const point_proj_t P, point_proj_t Q, const f2elm_t *A24minus, const f2elm_t *A24plus, const int e);

#define get_3_isog S2N_SIKE_P434_R3_NAMESPACE(get_3_isog)
void get_3_isog(const point_proj_t P, f2elm_t *A24minus, f2elm_t *A24plus, f2elm_t *coeff);

#define eval_3_isog S2N_SIKE_P434_R3_NAMESPACE(eval_3_isog)
void eval_3_isog(point_proj_t Q, const f2elm_t *coeff);

#define inv_3_way S2N_SIKE_P434_R3_NAMESPACE(inv_3_way)
void inv_3_way(f2elm_t *z1, f2elm_t *z2, f2elm_t *z3);

#define get_A S2N_SIKE_P434_R3_NAMESPACE(get_A)
void get_A(const f2elm_t *xP, const f2elm_t *xQ, const f2elm_t *xR, f2elm_t *A);

#define j_inv S2N_SIKE_P434_R3_NAMESPACE(j_inv)
void j_inv(const f2elm_t *A, const f2elm_t *C, f2elm_t *jinv);

#define LADDER3PT S2N_SIKE_P434_R3_NAMESPACE(LADDER3PT)
void LADDER3PT(const f2elm_t *xP, const f2elm_t *xQ, const f2elm_t *xPQ, const digit_t *m,
        const unsigned int AliceOrBob, point_proj_t R, const f2elm_t *A);
