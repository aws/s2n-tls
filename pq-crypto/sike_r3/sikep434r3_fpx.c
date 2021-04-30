/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: core functions over GF(p) and GF(p^2)
*********************************************************************************************/

#include <string.h>
#include "sikep434r3.h"
#include "sikep434r3_fp.h"
#include "sikep434r3_fpx.h"

static void fpmul_mont(const felm_t ma, const felm_t mb, felm_t mc);
static void to_mont(const felm_t a, felm_t mc);
static void from_mont(const felm_t ma, felm_t c);
static void fpsqr_mont(const felm_t ma, felm_t mc);
static unsigned int mp_sub(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords);
static void fpinv_chain_mont(felm_t a);
static void fpinv_mont(felm_t a);
static void to_fp2mont(const f2elm_t *a, f2elm_t *mc);
static void from_fp2mont(const f2elm_t *ma, f2elm_t *c);

/* Encoding digits to bytes according to endianness */
__inline static void encode_to_bytes(const digit_t* x, unsigned char* enc, int nbytes)
{
    if (is_big_endian()) {
        int ndigits = nbytes / sizeof(digit_t);
        int rem = nbytes % sizeof(digit_t);

        for (int i = 0; i < ndigits; i++) {
            digit_t temp = S2N_SIKE_P434_R3_BSWAP_DIGIT(x[i]);
            memcpy(enc + (i * sizeof(digit_t)), (unsigned char *)&temp, sizeof(digit_t));
        }

        if (rem) {
            digit_t ld = S2N_SIKE_P434_R3_BSWAP_DIGIT(x[ndigits]);
            memcpy(enc + ndigits * sizeof(digit_t), (unsigned char *) &ld, rem);
        }
    } else {
        memcpy(enc, (const unsigned char *) x, nbytes);
    }
}

/* Conversion of GF(p^2) element from Montgomery to standard representation,
 * and encoding by removing leading 0 bytes */
void fp2_encode(const f2elm_t *x, unsigned char *enc)
{
    f2elm_t t;

    from_fp2mont(x, &t);
    encode_to_bytes(t.e[0], enc, S2N_SIKE_P434_R3_FP2_ENCODED_BYTES / 2);
    encode_to_bytes(t.e[1], enc + S2N_SIKE_P434_R3_FP2_ENCODED_BYTES / 2, S2N_SIKE_P434_R3_FP2_ENCODED_BYTES / 2);
}

/* Parse byte sequence back into GF(p^2) element, and conversion to Montgomery representation */
void fp2_decode(const unsigned char *x, f2elm_t *dec)
{
    decode_to_digits(x, dec->e[0], S2N_SIKE_P434_R3_FP2_ENCODED_BYTES / 2, S2N_SIKE_P434_R3_NWORDS_FIELD);
    decode_to_digits(x + S2N_SIKE_P434_R3_FP2_ENCODED_BYTES / 2, dec->e[1], S2N_SIKE_P434_R3_FP2_ENCODED_BYTES / 2, S2N_SIKE_P434_R3_NWORDS_FIELD);
    to_fp2mont(dec, dec);
}

/* Multiprecision multiplication, c = a*b mod p. */
static void fpmul_mont(const felm_t ma, const felm_t mb, felm_t mc)
{
    dfelm_t temp = {0};

    mp_mul(ma, mb, temp, S2N_SIKE_P434_R3_NWORDS_FIELD);
    rdc_mont(temp, mc);
}

/* Conversion to Montgomery representation,
 * mc = a*R^2*R^(-1) mod p = a*R mod p, where a in [0, p-1].
 * The Montgomery constant R^2 mod p is the global value "Montgomery_R2".  */
static void to_mont(const felm_t a, felm_t mc)
{
    fpmul_mont(a, (const digit_t*)&Montgomery_R2, mc);
}

/* Conversion from Montgomery representation to standard representation,
 * c = ma*R^(-1) mod p = a mod p, where ma in [0, p-1]. */
static void from_mont(const felm_t ma, felm_t c)
{
    digit_t one[S2N_SIKE_P434_R3_NWORDS_FIELD] = {0};
    
    one[0] = 1;
    fpmul_mont(ma, one, c);
    fpcorrection434(c);
}

/* Copy wordsize digits, c = a, where lng(a) = nwords. */
void copy_words(const digit_t* a, digit_t* c, const unsigned int nwords)
{
    unsigned int i;
        
    for (i = 0; i < nwords; i++) {
        c[i] = a[i];
    }
}

/* Multiprecision squaring, c = a^2 mod p. */
static void fpsqr_mont(const felm_t ma, felm_t mc)
{
    dfelm_t temp = {0};

    mp_mul(ma, ma, temp, S2N_SIKE_P434_R3_NWORDS_FIELD);
    rdc_mont(temp, mc);
}

/* Copy a GF(p^2) element, c = a. */
void fp2copy(const f2elm_t *a, f2elm_t *c)
{
    fpcopy(a->e[0], c->e[0]);
    fpcopy(a->e[1], c->e[1]);
}

/* GF(p^2) division by two, c = a/2  in GF(p^2). */
void fp2div2(const f2elm_t *a, f2elm_t *c)
{
    fpdiv2_434(a->e[0], c->e[0]);
    fpdiv2_434(a->e[1], c->e[1]);
}

/* Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit. */
unsigned int mp_add(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{
    unsigned int i, carry = 0;
        
    for (i = 0; i < nwords; i++) {                      
        S2N_SIKE_P434_R3_ADDC(carry, a[i], b[i], carry, c[i]);
    }

    return carry;
}

/* GF(p^2) squaring using Montgomery arithmetic, c = a^2 in GF(p^2).
 * Inputs: a = a0+a1*i, where a0, a1 are in [0, 2*p-1]
 * Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1]  */
void fp2sqr_mont(const f2elm_t *a, f2elm_t *c)
{
    felm_t t1, t2, t3;

    mp_addfast(a->e[0], a->e[1], t1);       /* t1 = a0+a1 */
    mp_sub434_p4(a->e[0], a->e[1], t2);     /* t2 = a0-a1 */
    mp_addfast(a->e[0], a->e[0], t3);       /* t3 = 2a0 */
    fpmul_mont(t1, t2, c->e[0]);            /* c0 = (a0+a1)(a0-a1) */
    fpmul_mont(t3, a->e[1], c->e[1]);       /* c1 = 2a0*a1 */
}

/* Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit. */
static unsigned int mp_sub(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{
    unsigned int i, borrow = 0;

    for (i = 0; i < nwords; i++) {
        S2N_SIKE_P434_R3_SUBC(borrow, a[i], b[i], borrow, c[i]);
    }

    return borrow;
}

/* Multiprecision subtraction followed by addition with p*2^S2N_SIKE_P434_R3_MAXBITS_FIELD,
 * c = a-b+(p*2^S2N_SIKE_P434_R3_MAXBITS_FIELD) if a-b < 0, otherwise c=a-b. */
__inline static void mp_subaddfast(const digit_t* a, const digit_t* b, digit_t* c)
{
    felm_t t1;

    digit_t mask = 0 - (digit_t)mp_sub(a, b, c, 2*S2N_SIKE_P434_R3_NWORDS_FIELD);
    for (int i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        t1[i] = ((const digit_t *) p434)[i] & mask;
    }
    mp_addfast((digit_t*)&c[S2N_SIKE_P434_R3_NWORDS_FIELD], t1, (digit_t*)&c[S2N_SIKE_P434_R3_NWORDS_FIELD]);
}

/* Multiprecision subtraction, c = c-a-b, where lng(a) = lng(b) = 2*S2N_SIKE_P434_R3_NWORDS_FIELD. */
__inline static void mp_dblsubfast(const digit_t* a, const digit_t* b, digit_t* c)
{
    mp_sub(c, a, c, 2*S2N_SIKE_P434_R3_NWORDS_FIELD);
    mp_sub(c, b, c, 2*S2N_SIKE_P434_R3_NWORDS_FIELD);
}

/* GF(p^2) multiplication using Montgomery arithmetic, c = a*b in GF(p^2).
 * Inputs: a = a0+a1*i and b = b0+b1*i, where a0, a1, b0, b1 are in [0, 2*p-1]
 * Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1]  */
void fp2mul_mont(const f2elm_t *a, const f2elm_t *b, f2elm_t *c)
{
    felm_t t1, t2;
    dfelm_t tt1, tt2, tt3; 
    
    mp_addfast(a->e[0], a->e[1], t1);                                 /* t1 = a0+a1 */
    mp_addfast(b->e[0], b->e[1], t2);                                 /* t2 = b0+b1 */
    mp_mul(a->e[0], b->e[0], tt1, S2N_SIKE_P434_R3_NWORDS_FIELD);     /* tt1 = a0*b0 */
    mp_mul(a->e[1], b->e[1], tt2, S2N_SIKE_P434_R3_NWORDS_FIELD);     /* tt2 = a1*b1 */
    mp_mul(t1, t2, tt3, S2N_SIKE_P434_R3_NWORDS_FIELD);               /* tt3 = (a0+a1)*(b0+b1) */
    mp_dblsubfast(tt1, tt2, tt3);                                     /* tt3 = (a0+a1)*(b0+b1) - a0*b0 - a1*b1 */
    mp_subaddfast(tt1, tt2, tt1);                                     /* tt1 = a0*b0 - a1*b1 + p*2^S2N_SIKE_P434_R3_MAXBITS_FIELD if a0*b0 - a1*b1 < 0, else tt1 = a0*b0 - a1*b1 */
    rdc_mont(tt3, c->e[1]);                                           /* c[1] = (a0+a1)*(b0+b1) - a0*b0 - a1*b1 */
    rdc_mont(tt1, c->e[0]);                                           /* c[0] = a0*b0 - a1*b1 */
}

/* Chain to compute a^(p-3)/4 using Montgomery arithmetic. */
static void fpinv_chain_mont(felm_t a)
{
    unsigned int i, j;
    felm_t t[31], tt;

    /* Precomputed table */
    fpsqr_mont(a, tt);
    fpmul_mont(a, tt, t[0]);
    for (i = 0; i <= 29; i++) {
        fpmul_mont(t[i], tt, t[i + 1]);
    }

    fpcopy(a, tt);
    for (i = 0; i < 7; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 10; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[14], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[23], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[13], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[24], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[7], tt, tt);
    for (i = 0; i < 8; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[12], tt, tt);
    for (i = 0; i < 8; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[30], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[1], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[30], tt, tt);
    for (i = 0; i < 7; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[21], tt, tt);
    for (i = 0; i < 9; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 9; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[19], tt, tt);
    for (i = 0; i < 9; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[1], tt, tt);
    for (i = 0; i < 7; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[24], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[26], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[16], tt, tt);
    for (i = 0; i < 7; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 7; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 7; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 9; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[20], tt, tt);
    for (i = 0; i < 8; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[9], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[25], tt, tt);
    for (i = 0; i < 9; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[30], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[26], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 7; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[28], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 6; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 9; i++) {
        fpsqr_mont(tt, tt);
    }
    fpmul_mont(t[22], tt, tt);
    for (j = 0; j < 35; j++) {
        for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
        fpmul_mont(t[30], tt, tt);
    }
    fpcopy(tt, a);
}

/* Field inversion using Montgomery arithmetic, a = a^(-1)*R mod p. */
static void fpinv_mont(felm_t a)
{
    felm_t tt;

    fpcopy(a, tt);
    fpinv_chain_mont(tt);
    fpsqr_mont(tt, tt);
    fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, a);
}

/* GF(p^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2). */
void fp2inv_mont(f2elm_t *a)
{
    f2elm_t t1;

    fpsqr_mont(a->e[0], t1.e[0]);                         /* t10 = a0^2 */
    fpsqr_mont(a->e[1], t1.e[1]);                         /* t11 = a1^2 */
    fpadd434(t1.e[0], t1.e[1], t1.e[0]);                  /* t10 = a0^2+a1^2 */
    fpinv_mont(t1.e[0]);                                  /* t10 = (a0^2+a1^2)^-1 */
    fpneg434(a->e[1]);                                    /* a = a0-i*a1 */
    fpmul_mont(a->e[0], t1.e[0], a->e[0]);
    fpmul_mont(a->e[1], t1.e[0], a->e[1]);                /* a = (a0-i*a1)*(a0^2+a1^2)^-1 */
}

/* Conversion of a GF(p^2) element to Montgomery representation,
 * mc_i = a_i*R^2*R^(-1) = a_i*R in GF(p^2).  */
static void to_fp2mont(const f2elm_t *a, f2elm_t *mc)
{
    to_mont(a->e[0], mc->e[0]);
    to_mont(a->e[1], mc->e[1]);
}

/* Conversion of a GF(p^2) element from Montgomery representation to standard representation,
 * c_i = ma_i*R^(-1) = a_i in GF(p^2). */
static void from_fp2mont(const f2elm_t *ma, f2elm_t *c)
{
    from_mont(ma->e[0], c->e[0]);
    from_mont(ma->e[1], c->e[1]);
}

/* Multiprecision right shift by one. */
void mp_shiftr1(digit_t* x, const unsigned int nwords)
{
    unsigned int i;

    for (i = 0; i < nwords-1; i++) {
        S2N_SIKE_P434_R3_SHIFTR(x[i+1], x[i], 1, x[i], S2N_SIKE_P434_R3_RADIX);
    }
    x[nwords-1] >>= 1;
}

void decode_to_digits(const unsigned char* x, digit_t* dec, int nbytes, int ndigits)
{
    dec[ndigits - 1] = 0;
    memcpy((unsigned char*)dec, x, nbytes);

    if (is_big_endian()) {
        for (int i = 0; i < ndigits; i++) {
            dec[i] = S2N_SIKE_P434_R3_BSWAP_DIGIT(dec[i]);
        }
    }
}

void fpcopy(const felm_t a, felm_t c)
{
    unsigned int i;

    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        c[i] = a[i];
    }
}

void fpzero(felm_t a)
{
    unsigned int i;

    for (i = 0; i < S2N_SIKE_P434_R3_NWORDS_FIELD; i++) {
        a[i] = 0;
    }
}

void fp2add(const f2elm_t *a, const f2elm_t *b, f2elm_t *c)
{
    fpadd434(a->e[0], b->e[0], c->e[0]);
    fpadd434(a->e[1], b->e[1], c->e[1]);
}

void fp2sub(const f2elm_t *a, const f2elm_t *b, f2elm_t *c)
{
    fpsub434(a->e[0], b->e[0], c->e[0]);
    fpsub434(a->e[1], b->e[1], c->e[1]);
}

void mp_addfast(const digit_t* a, const digit_t* b, digit_t* c)
{
    mp_add(a, b, c, S2N_SIKE_P434_R3_NWORDS_FIELD);
}

void mp2_add(const f2elm_t *a, const f2elm_t *b, f2elm_t *c)
{
    mp_addfast(a->e[0], b->e[0], c->e[0]);
    mp_addfast(a->e[1], b->e[1], c->e[1]);
}

void mp2_sub_p2(const f2elm_t *a, const f2elm_t *b, f2elm_t *c)
{
    mp_sub434_p2(a->e[0], b->e[0], c->e[0]);
    mp_sub434_p2(a->e[1], b->e[1], c->e[1]);
}
