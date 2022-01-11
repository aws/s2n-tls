/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: modular arithmetic for P434
*********************************************************************************************/

#include "sikep434r3.h"
#include "pq-crypto/s2n_pq.h"
#include "sikep434r3_fp.h"
#include "sikep434r3_fpx.h"
#include "sikep434r3_fp_x64_asm.h"

/* Multiprecision subtraction with correction with 2*p, c = a-b+2p. */
void mp_sub434_p2(const digit_t* a, const digit_t* b, digit_t* c)
{
#if defined(S2N_SIKE_P434_R3_ASM)
    if (s2n_sikep434r3_asm_is_enabled()) {
        mp_sub434_p2_asm(a, b, c);
        return;
    }
#endif

    unsigned int i, borrow = 0;

    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_SUBC(borrow, a[i], b[i], borrow, c[i]);
    }

    borrow = 0;
    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_ADDC(borrow, c[i], ((const digit_t*)p434x2)[i], borrow, c[i]);
    }
}

/* Multiprecision subtraction with correction with 4*p, c = a-b+4p. */
void mp_sub434_p4(const digit_t* a, const digit_t* b, digit_t* c)
{
#if defined(S2N_SIKE_P434_R3_ASM)
    if (s2n_sikep434r3_asm_is_enabled()) {
        mp_sub434_p4_asm(a, b, c);
        return;
    }
#endif

    unsigned int i, borrow = 0;

    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_SUBC(borrow, a[i], b[i], borrow, c[i]);
    }

    borrow = 0;
    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_ADDC(borrow, c[i], ((const digit_t*)p434x4)[i], borrow, c[i]);
    }
}

/* Modular addition, c = a+b mod p434.
 * Inputs: a, b in [0, 2*p434-1]
 * Output: c in [0, 2*p434-1] */
void fpadd434(const digit_t* a, const digit_t* b, digit_t* c)
{
#if defined(S2N_SIKE_P434_R3_ASM)
    if (s2n_sikep434r3_asm_is_enabled()) {
        fpadd434_asm(a, b, c);
        return;
    }
#endif
    unsigned int i, carry = 0;
    digit_t mask;

    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_ADDC(carry, a[i], b[i], carry, c[i]);
    }

    carry = 0;
    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_SUBC(carry, c[i], ((const digit_t*)p434x2)[i], carry, c[i]);
    }
    mask = 0 - (digit_t)carry;

    carry = 0;
    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_ADDC(carry, c[i], ((const digit_t*)p434x2)[i] & mask, carry, c[i]);
    }
}

/* Modular subtraction, c = a-b mod p434.
 * Inputs: a, b in [0, 2*p434-1]
 * Output: c in [0, 2*p434-1] */
void fpsub434(const digit_t* a, const digit_t* b, digit_t* c)
{
#if defined(S2N_SIKE_P434_R3_ASM)
    if (s2n_sikep434r3_asm_is_enabled()) {
        fpsub434_asm(a, b, c);
        return;
    }
#endif

    unsigned int i, borrow = 0;
    digit_t mask;

    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_SUBC(borrow, a[i], b[i], borrow, c[i]);
    }
    mask = 0 - (digit_t)borrow;

    borrow = 0;
    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_ADDC(borrow, c[i], ((const digit_t*)p434x2)[i] & mask, borrow, c[i]);
    }
}

/* Modular negation, a = -a mod p434.
 * Input/output: a in [0, 2*p434-1]  */
void fpneg434(digit_t* a)
{
    unsigned int i, borrow = 0;

    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_SUBC(borrow, ((const digit_t*)p434x2)[i], a[i], borrow, a[i]);
    }
}

/* Modular division by two, c = a/2 mod p434.
 * Input : a in [0, 2*p434-1]
 * Output: c in [0, 2*p434-1] */
void fpdiv2_434(const digit_t* a, digit_t* c)
{
    unsigned int i, carry = 0;
    digit_t mask;

    mask = 0 - (digit_t)(a[0] & 1); /* If a is odd compute a+p434 */
    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_ADDC(carry, a[i], ((const digit_t*)p434)[i] & mask, carry, c[i]);
    }

    mp_shiftr1(c, S2N_SIKE_P434_R3_NWORDS_FIELD);
}

/* Modular correction to reduce field element a in [0, 2*p434-1] to [0, p434-1]. */
void fpcorrection434(digit_t* a)
{
    unsigned int i, borrow = 0;
    digit_t mask;

    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_SUBC(borrow, a[i], ((const digit_t*)p434)[i], borrow, a[i]);
    }
    mask = 0 - (digit_t)borrow;

    borrow = 0;
    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        S2N_SIKE_P434_R3_ADDC(borrow, a[i], ((const digit_t*)p434)[i] & mask, borrow, a[i]);
    }
}

/* Digit multiplication, digit * digit -> 2-digit result */
void digit_x_digit(const digit_t a, const digit_t b, digit_t* c)
{
    register digit_t al, ah, bl, bh, temp;
    digit_t albl, albh, ahbl, ahbh, res1, res2, res3, carry;
    digit_t mask_low = (digit_t)(-1) >> (sizeof(digit_t)*4), mask_high = (digit_t)(-1) << (sizeof(digit_t)*4);

    al = a & mask_low;                        /* Low part */
    ah = a >> (sizeof(digit_t) * 4);          /* High part */
    bl = b & mask_low;
    bh = b >> (sizeof(digit_t) * 4);

    albl = al*bl;
    albh = al*bh;
    ahbl = ah*bl;
    ahbh = ah*bh;
    c[0] = albl & mask_low;                   /* C00 */

    res1 = albl >> (sizeof(digit_t) * 4);
    res2 = ahbl & mask_low;
    res3 = albh & mask_low;  
    temp = res1 + res2 + res3;
    carry = temp >> (sizeof(digit_t) * 4);
    c[0] ^= temp << (sizeof(digit_t) * 4);    /* C01 */

    res1 = ahbl >> (sizeof(digit_t) * 4);
    res2 = albh >> (sizeof(digit_t) * 4);
    res3 = ahbh & mask_low;
    temp = res1 + res2 + res3 + carry;
    c[1] = temp & mask_low;                   /* C10 */
    carry = temp & mask_high; 
    c[1] ^= (ahbh & mask_high) + carry;       /* C11 */
}

/* Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords. */
void mp_mul(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{
#if defined(S2N_SIKE_P434_R3_ASM)
    if (s2n_sikep434r3_asm_is_enabled()) {
        S2N_SIKE_P434_R3_UNREFERENCED_PARAMETER(nwords);
        mul434_asm(a, b, c);
        return;
    }
#endif

    unsigned int i, j;
    digit_t t = 0, u = 0, v = 0, UV[2];
    unsigned int carry;
    
    for (i = 0; i < nwords; i++) {
        for (j = 0; j <= i; j++) {
            S2N_SIKE_P434_R3_MUL(a[j], b[i-j], UV+1, UV[0]);
            S2N_SIKE_P434_R3_ADDC(0, UV[0], v, carry, v);
            S2N_SIKE_P434_R3_ADDC(carry, UV[1], u, carry, u);
            t += carry;
        }
        c[i] = v;
        v = u; 
        u = t;
        t = 0;
    }

    for (i = nwords; i < 2*nwords-1; i++) {
        for (j = i-nwords+1; j < nwords; j++) {
            S2N_SIKE_P434_R3_MUL(a[j], b[i-j], UV+1, UV[0]);
            S2N_SIKE_P434_R3_ADDC(0, UV[0], v, carry, v);
            S2N_SIKE_P434_R3_ADDC(carry, UV[1], u, carry, u);
            t += carry;
        }
        c[i] = v;
        v = u; 
        u = t;
        t = 0;
    }
    c[2*nwords-1] = v; 
}

/* Efficient Montgomery reduction using comba and exploiting the special form of the prime p434.
 * mc = ma*R^-1 mod p434x2, where R = 2^448.
 * If ma < 2^448*p434, the output mc is in the range [0, 2*p434-1].
 * ma is assumed to be in Montgomery representation. */
void rdc_mont(digit_t* ma, digit_t* mc)
{
#if defined(S2N_SIKE_P434_R3_ASM)
    if (s2n_sikep434r3_asm_is_enabled()) {
        rdc434_asm(ma, mc);
        return;
    }
#endif

    unsigned int i, j, carry, count = S2N_SIKE_P434_R3_ZERO_WORDS;
    digit_t UV[2], t = 0, u = 0, v = 0;

    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        mc[i] = 0;
    }

    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        for (j = 0; j < i; j++) {
            if (j < (i-S2N_SIKE_P434_R3_ZERO_WORDS+1)) {
                S2N_SIKE_P434_R3_MUL(mc[j], ((const digit_t*)p434p1)[i-j], UV+1, UV[0]);
                S2N_SIKE_P434_R3_ADDC(0, UV[0], v, carry, v);
                S2N_SIKE_P434_R3_ADDC(carry, UV[1], u, carry, u);
                t += carry; 
            }
        }
        S2N_SIKE_P434_R3_ADDC(0, v, ma[i], carry, v);
        S2N_SIKE_P434_R3_ADDC(carry, u, 0, carry, u);
        t += carry; 
        mc[i] = v;
        v = u;
        u = t;
        t = 0;
    }    

    for (i = S2N_SIKE_P434_R3_NWORDS_FIELD; i < 2*S2N_SIKE_P434_R3_NWORDS_FIELD-1; i++) {
        if (count > 0) {
            count -= 1;
        }
        for (j = i-S2N_SIKE_P434_R3_NWORDS_FIELD+1; j < S2N_SIKE_P434_R3_NWORDS_FIELD; j++) {
            if (j < (S2N_SIKE_P434_R3_NWORDS_FIELD-count)) {
                S2N_SIKE_P434_R3_MUL(mc[j], ((const digit_t*)p434p1)[i-j], UV+1, UV[0]);
                S2N_SIKE_P434_R3_ADDC(0, UV[0], v, carry, v);
                S2N_SIKE_P434_R3_ADDC(carry, UV[1], u, carry, u);
                t += carry;
            }
        }
        S2N_SIKE_P434_R3_ADDC(0, v, ma[i], carry, v);
        S2N_SIKE_P434_R3_ADDC(carry, u, 0, carry, u);
        t += carry; 
        mc[i-S2N_SIKE_P434_R3_NWORDS_FIELD] = v;
        v = u;
        u = t;
        t = 0;
    }

    /* `carry` isn't read after this, but it's still a necessary argument to the macro */
    /* cppcheck-suppress unreadVariable */
    S2N_SIKE_P434_R3_ADDC(0, v, ma[2*S2N_SIKE_P434_R3_NWORDS_FIELD-1], carry, v);
    mc[S2N_SIKE_P434_R3_NWORDS_FIELD-1] = v;
}
