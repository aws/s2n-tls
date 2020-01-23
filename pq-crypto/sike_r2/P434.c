/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny parameters and generation of functions for P434
*********************************************************************************************/

#include "P434_api.h"
#include "P434_internal.h"

// Encoding of field elements, elements over Z_order, elements over GF(p^2) and elliptic curve points:
// --------------------------------------------------------------------------------------------------
// Elements over GF(p) and Z_order are encoded with the least significant octet (and digit) located at the leftmost position (i.e., little endian format).
// Elements (a+b*i) over GF(p^2), where a and b are defined over GF(p), are encoded as {a, b}, with a in the least significant position.
// Elliptic curve points P = (x,y) are encoded as {x, y}, with x in the least significant position.
// Internally, the number of digits used to represent all these elements is obtained by approximating the number of bits to the immediately greater multiple of 32.
// For example, a 434-bit field element is represented with Ceil(434 / 64) = 7 64-bit digits or Ceil(434 / 32) = 14 32-bit digits.

//
// Curve isogeny system "SIDHp434". Base curve: Montgomery curve By^2 = Cx^3 + Ax^2 + Cx defined over GF(p434^2), where A=6, B=1, C=1 and p434 = 2^216*3^137-1
//


// The constants p434, p434p1, and p434x2 have been duplicated in
// fp_x64_asm.S. If, for any reason, the constants are changed in
// one file, they should be updated in the other file as well.
const uint64_t p434[NWORDS64_FIELD] = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFDC1767AE2FFFFFF,
                                              0x7BC65C783158AEA3, 0x6CFC5FD681C52056, 0x0002341F27177344};
const uint64_t p434p1[NWORDS64_FIELD] = {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0xFDC1767AE3000000,
                                                0x7BC65C783158AEA3, 0x6CFC5FD681C52056, 0x0002341F27177344};
const uint64_t p434x2[NWORDS64_FIELD] = {0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFB82ECF5C5FFFFFF,
                                                0xF78CB8F062B15D47, 0xD9F8BFAD038A40AC, 0x0004683E4E2EE688};
// Order of Alice's subgroup
const uint64_t Alice_order[NWORDS64_ORDER] = {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000001000000};
// Order of Bob's subgroup
const uint64_t Bob_order[NWORDS64_ORDER] = {0x58AEA3FDC1767AE3, 0xC520567BC65C7831, 0x1773446CFC5FD681, 0x0000000002341F27};
// Alice's generator values {XPA0 + XPA1*i, XQA0 + xQA1*i, XRA0 + XRA1*i} in GF(p434^2), expressed in Montgomery representation
const uint64_t A_gen[6 * NWORDS64_FIELD] = {0x05ADF455C5C345BF, 0x91935C5CC767AC2B, 0xAFE4E879951F0257, 0x70E792DC89FA27B1,
                                                   0xF797F526BB48C8CD, 0x2181DB6131AF621F, 0x00000A1C08B1ECC4, // XPA0
                                                   0x74840EB87CDA7788, 0x2971AA0ECF9F9D0B, 0xCB5732BDF41715D5, 0x8CD8E51F7AACFFAA,
                                                   0xA7F424730D7E419F, 0xD671EB919A179E8C, 0x0000FFA26C5A924A, // XPA1
                                                   0xFEC6E64588B7273B, 0xD2A626D74CBBF1C6, 0xF8F58F07A78098C7, 0xE23941F470841B03,
                                                   0x1B63EDA2045538DD, 0x735CFEB0FFD49215, 0x0001C4CB77542876, // XQA0
                                                   0xADB0F733C17FFDD6, 0x6AFFBD037DA0A050, 0x680EC43DB144E02F, 0x1E2E5D5FF524E374,
                                                   0xE2DDA115260E2995, 0xA6E4B552E2EDE508, 0x00018ECCDDF4B53E, // XQA1
                                                   0x01BA4DB518CD6C7D, 0x2CB0251FE3CC0611, 0x259B0C6949A9121B, 0x60E17AC16D2F82AD,
                                                   0x3AA41F1CE175D92D, 0x413FBE6A9B9BC4F3, 0x00022A81D8D55643, // XRA0
                                                   0xB8ADBC70FC82E54A, 0xEF9CDDB0D5FADDED, 0x5820C734C80096A0, 0x7799994BAA96E0E4,
                                                   0x044961599E379AF8, 0xDB2B94FBF09F27E2, 0x0000B87FC716C0C6}; // XRA1
// Bob's generator values {XPB0, XQB0, XRB0 + XRB1*i} in GF(p434^2), expressed in Montgomery representation
const uint64_t B_gen[6 * NWORDS64_FIELD] = {0x6E5497556EDD48A3, 0x2A61B501546F1C05, 0xEB919446D049887D, 0x5864A4A69D450C4F,
                                                   0xB883F276A6490D2B, 0x22CC287022D5F5B9, 0x0001BED4772E551F, // XPB0
                                                   0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                                                   0x0000000000000000, 0x0000000000000000, 0x0000000000000000, // XPB1
                                                   0xFAE2A3F93D8B6B8E, 0x494871F51700FE1C, 0xEF1A94228413C27C, 0x498FF4A4AF60BD62,
                                                   0xB00AD2A708267E8A, 0xF4328294E017837F, 0x000034080181D8AE, // XQB0
                                                   0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
                                                   0x0000000000000000, 0x0000000000000000, 0x0000000000000000, // XQB1
                                                   0x283B34FAFEFDC8E4, 0x9208F44977C3E647, 0x7DEAE962816F4E9A, 0x68A2BA8AA262EC9D,
                                                   0x8176F112EA43F45B, 0x02106D022634F504, 0x00007E8A50F02E37, // XRB0
                                                   0xB378B7C1DA22CCB1, 0x6D089C99AD1D9230, 0xEBE15711813E2369, 0x2B35A68239D48A53,
                                                   0x445F6FD138407C93, 0xBEF93B29A3F6B54B, 0x000173FA910377D3}; // XRB1
// Montgomery constant Montgomery_R2 = (2^448)^2 mod p434
const uint64_t Montgomery_R2[NWORDS64_FIELD] = {0x28E55B65DCD69B30, 0xACEC7367768798C2, 0xAB27973F8311688D, 0x175CC6AF8D6C7C0B,
                                                       0xABCD92BF2DDE347E, 0x69E16A61C7686D9A, 0x000025A89BCDD12A};
// Value one in Montgomery representation
const uint64_t Montgomery_one[NWORDS64_FIELD] = {0x000000000000742C, 0x0000000000000000, 0x0000000000000000, 0xB90FF404FC000000,
                                                        0xD801A4FB559FACD4, 0xE93254545F77410C, 0x0000ECEEA7BD2EDA};

// Fixed parameters for isogeny tree computation
const unsigned int strat_Alice[MAX_Alice - 1] = {
    48, 28, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 13, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1,
    1, 1, 5, 4, 2, 1, 1, 2, 1, 1, 2, 1, 1, 1, 21, 12, 7, 4, 2, 1, 1, 2, 1, 1, 3, 2, 1, 1, 1, 1, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 9, 5, 3, 2, 1, 1,
    1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1};

const unsigned int strat_Bob[MAX_Bob - 1] = {
    66, 33, 17, 9, 5, 3, 2, 1, 1, 1, 1, 2, 1, 1, 1, 4, 2, 1, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 1,
    2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 32, 16, 8, 4, 3, 1, 1, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2,
    1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 16, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1, 8, 4, 2, 1, 1, 2, 1, 1, 4, 2, 1, 1, 2, 1, 1};

// Setting up macro defines and including GF(p), GF(p^2), curve, isogeny and kex functions
#define fpcopy fpcopy434
#define fpzero fpzero434
#define fpadd fpadd434
#define fpsub fpsub434
#define fpneg fpneg434
#define fpdiv2 fpdiv2_434
#define fpcorrection fpcorrection434
#define fpmul_mont fpmul434_mont
#define fpsqr_mont fpsqr434_mont
#define fpinv_mont fpinv434_mont
#define fpinv_chain_mont fpinv434_chain_mont
#define fp2copy fp2copy434
#define fp2zero fp2zero434
#define fp2add fp2add434
#define fp2sub fp2sub434
#define fp2neg fp2neg434
#define fp2div2 fp2div2_434
#define fp2correction fp2correction434
#define fp2mul_mont fp2mul434_mont
#define fp2sqr_mont fp2sqr434_mont
#define fp2inv_mont fp2inv434_mont
#define mp_add_asm mp_add434_asm
#define mp_subaddx2_asm mp_subadd434x2_asm
#define mp_dblsubx2_asm mp_dblsub434x2_asm
#define random_mod_order_A oqs_kem_sidh_p434_random_mod_order_A
#define random_mod_order_B oqs_kem_sidh_p434_random_mod_order_B
#define EphemeralKeyGeneration_A oqs_kem_sidh_p434_EphemeralKeyGeneration_A
#define EphemeralKeyGeneration_B oqs_kem_sidh_p434_EphemeralKeyGeneration_B
#define EphemeralSecretAgreement_A oqs_kem_sidh_p434_EphemeralSecretAgreement_A
#define EphemeralSecretAgreement_B oqs_kem_sidh_p434_EphemeralSecretAgreement_B

#if defined(S2N_PQ_ASM)
#include "fp_x64.c"
#else
#include "fp_generic.c"
#endif

#include "fpx.c"
#include "ec_isogeny.c"
#include "sidh.c"
#include "sike_p434_r2_kem.c"
