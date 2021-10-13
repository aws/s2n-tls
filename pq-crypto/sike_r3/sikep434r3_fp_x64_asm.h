/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: x86_64 assembly optimized modular arithmetic for P434
*********************************************************************************************/

#pragma once

#if defined(S2N_SIKE_P434_R3_ASM)

#define fpadd434_asm S2N_SIKE_P434_R3_NAMESPACE(fpadd434_asm)
void fpadd434_asm(const digit_t* a, const digit_t* b, digit_t* c);

#define fpsub434_asm S2N_SIKE_P434_R3_NAMESPACE(fpsub434_asm)
void fpsub434_asm(const digit_t* a, const digit_t* b, digit_t* c);

#define mul434_asm S2N_SIKE_P434_R3_NAMESPACE(mul434_asm)
void mul434_asm(const digit_t* a, const digit_t* b, digit_t* c);

#define rdc434_asm S2N_SIKE_P434_R3_NAMESPACE(rdc434_asm)
void rdc434_asm(digit_t* ma, digit_t* mc);

#define mp_add434_asm S2N_SIKE_P434_R3_NAMESPACE(mp_add434_asm)
void mp_add434_asm(const digit_t* a, const digit_t* b, digit_t* c);

#define mp_subadd434x2_asm S2N_SIKE_P434_R3_NAMESPACE(mp_subadd434x2_asm)
void mp_subadd434x2_asm(const digit_t* a, const digit_t* b, digit_t* c);

#define mp_dblsub434x2_asm S2N_SIKE_P434_R3_NAMESPACE(mp_dblsub434x2_asm)
void mp_dblsub434x2_asm(const digit_t* a, const digit_t* b, digit_t* c);

#define mp_sub434_p2_asm S2N_SIKE_P434_R3_NAMESPACE(mp_sub434_p2_asm)
void mp_sub434_p2_asm(const digit_t* a, const digit_t* b, digit_t* c);

#define mp_sub434_p4_asm S2N_SIKE_P434_R3_NAMESPACE(mp_sub434_p4_asm)
void mp_sub434_p4_asm(const digit_t* a, const digit_t* b, digit_t* c);

#endif
