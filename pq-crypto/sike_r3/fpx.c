/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: core functions over GF(p) and GF(p^2)
*********************************************************************************************/

#include <string.h>


void clear_words(void* mem, digit_t nwords)
{ // Clear digits from memory. "nwords" indicates the number of digits to be zeroed.
  // This function uses the volatile type qualifier to inform the compiler not to optimize out the memory clearing.
    volatile digit_t *v = mem; 

    for (unsigned int i = 0; i < nwords; i++)
        v[i] = 0;
}


int8_t ct_compare(const uint8_t *a, const uint8_t *b, unsigned int len) 
{ // Compare two byte arrays in constant time.
  // Returns 0 if the byte arrays are equal, -1 otherwise.
    uint8_t r = 0;

    for (unsigned int i = 0; i < len; i++)
        r |= a[i] ^ b[i];

    return (-(int8_t)r) >> (8*sizeof(uint8_t)-1);
}


void ct_cmov(uint8_t *r, const uint8_t *a, unsigned int len, int8_t selector) 
{ // Conditional move in constant time.
  // If selector = -1 then load r with a, else if selector = 0 then keep r.

    for (unsigned int i = 0; i < len; i++)
        r[i] ^= selector & (a[i] ^ r[i]);
}


__inline static void encode_to_bytes(const digit_t* x, unsigned char* enc, int nbytes)
{ // Encoding digits to bytes according to endianness
#ifdef _BIG_ENDIAN_
    int ndigits = nbytes / sizeof(digit_t);
    int rem = nbytes % sizeof(digit_t);

    for (int i = 0; i < ndigits; i++)
        ((digit_t*)enc)[i] = BSWAP_DIGIT(x[i]);
    if (rem) {
        digit_t ld = BSWAP_DIGIT(x[ndigits]);
        memcpy(enc + ndigits*sizeof(digit_t), (unsigned char*)&ld, rem);
    }
#else    
    memcpy(enc, (const unsigned char*)x, nbytes);
#endif
}


__inline static void decode_to_digits(const unsigned char* x, digit_t* dec, int nbytes, int ndigits)
{ // Decoding bytes to digits according to endianness

    dec[ndigits - 1] = 0;
    memcpy((unsigned char*)dec, x, nbytes);
#ifdef _BIG_ENDIAN_
    for (int i = 0; i < ndigits; i++)
        dec[i] = BSWAP_DIGIT(dec[i]);
#endif
}


static void fp2_encode(const f2elm_t x, unsigned char *enc)
{ // Conversion of GF(p^2) element from Montgomery to standard representation, and encoding by removing leading 0 bytes
    f2elm_t t;

    from_fp2mont(x, t);
    encode_to_bytes(t[0], enc, FP2_ENCODED_BYTES / 2);
    encode_to_bytes(t[1], enc + FP2_ENCODED_BYTES / 2, FP2_ENCODED_BYTES / 2);
}


static void fp2_decode(const unsigned char *x, f2elm_t dec)
{ // Parse byte sequence back into GF(p^2) element, and conversion to Montgomery representation

    decode_to_digits(x, dec[0], FP2_ENCODED_BYTES / 2, NWORDS_FIELD);
    decode_to_digits(x + FP2_ENCODED_BYTES / 2, dec[1], FP2_ENCODED_BYTES / 2, NWORDS_FIELD);
    to_fp2mont(dec, dec);
}


__inline void fpcopy(const felm_t a, felm_t c)
{ // Copy a field element, c = a.
    unsigned int i;

    for (i = 0; i < NWORDS_FIELD; i++)
        c[i] = a[i];
}


__inline void fpzero(felm_t a)
{ // Zero a field element, a = 0.
    unsigned int i;

    for (i = 0; i < NWORDS_FIELD; i++)
        a[i] = 0;
}


void to_mont(const felm_t a, felm_t mc)
{ // Conversion to Montgomery representation,
  // mc = a*R^2*R^(-1) mod p = a*R mod p, where a in [0, p-1].
  // The Montgomery constant R^2 mod p is the global value "Montgomery_R2". 

    fpmul_mont(a, (digit_t*)&Montgomery_R2, mc);
}


void from_mont(const felm_t ma, felm_t c)
{ // Conversion from Montgomery representation to standard representation,
  // c = ma*R^(-1) mod p = a mod p, where ma in [0, p-1].
    digit_t one[NWORDS_FIELD] = {0};
    
    one[0] = 1;
    fpmul_mont(ma, one, c);
    fpcorrection(c);
}


void copy_words(const digit_t* a, digit_t* c, const unsigned int nwords)
{ // Copy wordsize digits, c = a, where lng(a) = nwords.
    unsigned int i;
        
    for (i = 0; i < nwords; i++)                      
        c[i] = a[i];
}

void fpmul_mont(const felm_t ma, const felm_t mb, felm_t mc)
{ // Multiprecision multiplication, c = a*b mod p.
    dfelm_t temp = {0};

    mp_mul(ma, mb, temp, NWORDS_FIELD);
    rdc_mont(temp, mc);
}


void fpsqr_mont(const felm_t ma, felm_t mc)
{ // Multiprecision squaring, c = a^2 mod p.
    dfelm_t temp = {0};

    mp_mul(ma, ma, temp, NWORDS_FIELD);
    rdc_mont(temp, mc);
}


void fpinv_mont(felm_t a)
{ // Field inversion using Montgomery arithmetic, a = a^(-1)*R mod p.
    felm_t tt;

    fpcopy(a, tt);
    fpinv_chain_mont(tt);
    fpsqr_mont(tt, tt);
    fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, a);
}


void fp2copy(const f2elm_t a, f2elm_t c)
{ // Copy a GF(p^2) element, c = a.
    fpcopy(a[0], c[0]);
    fpcopy(a[1], c[1]);
}


void fp2zero(f2elm_t a)
{ // Zero a GF(p^2) element, a = 0.
    fpzero(a[0]);
    fpzero(a[1]);
}


void fp2neg(f2elm_t a)
{ // GF(p^2) negation, a = -a in GF(p^2).
    fpneg(a[0]);
    fpneg(a[1]);
}


__inline void fp2add(const f2elm_t a, const f2elm_t b, f2elm_t c)           
{ // GF(p^2) addition, c = a+b in GF(p^2).
    fpadd(a[0], b[0], c[0]);
    fpadd(a[1], b[1], c[1]);
}


__inline void fp2sub(const f2elm_t a, const f2elm_t b, f2elm_t c)          
{ // GF(p^2) subtraction, c = a-b in GF(p^2).
    fpsub(a[0], b[0], c[0]);
    fpsub(a[1], b[1], c[1]);
}


void fp2div2(const f2elm_t a, f2elm_t c)          
{ // GF(p^2) division by two, c = a/2  in GF(p^2).
    fpdiv2(a[0], c[0]);
    fpdiv2(a[1], c[1]);
}


void fp2correction(f2elm_t a)
{ // Modular correction, a = a in GF(p^2).
    fpcorrection(a[0]);
    fpcorrection(a[1]);
}


__inline static void mp_addfast(const digit_t* a, const digit_t* b, digit_t* c)
{ // Multiprecision addition, c = a+b.    
#if (OS_TARGET == OS_WIN) || defined(GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM)

    mp_add(a, b, c, NWORDS_FIELD);
    
#elif (OS_TARGET == OS_NIX)                 
    
    mp_add_asm(a, b, c);    

#endif
}


__inline static void mp2_add(const f2elm_t a, const f2elm_t b, f2elm_t c)       
{ // GF(p^2) addition without correction, c = a+b in GF(p^2). 
    mp_addfast(a[0], b[0], c[0]);
    mp_addfast(a[1], b[1], c[1]);
}


__inline static void mp2_sub_p2(const f2elm_t a, const f2elm_t b, f2elm_t c)       
{ // GF(p^2) subtraction with correction with 2*p, c = a-b+2p in GF(p^2).    
    mp_sub_p2(a[0], b[0], c[0]);  
    mp_sub_p2(a[1], b[1], c[1]);
}


__inline static void mp2_sub_p4(const f2elm_t a, const f2elm_t b, f2elm_t c)       
{ // GF(p^2) subtraction with correction with 4*p, c = a-b+4p in GF(p^2). 
    mp_sub_p4(a[0], b[0], c[0]);  
    mp_sub_p4(a[1], b[1], c[1]); 
}


__inline unsigned int mp_add(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{ // Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit.
    unsigned int i, carry = 0;
        
    for (i = 0; i < nwords; i++) {                      
        ADDC(carry, a[i], b[i], carry, c[i]);
    }

    return carry;
}


void fp2sqr_mont(const f2elm_t a, f2elm_t c)
{ // GF(p^2) squaring using Montgomery arithmetic, c = a^2 in GF(p^2).
  // Inputs: a = a0+a1*i, where a0, a1 are in [0, 2*p-1] 
  // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1] 
    felm_t t1, t2, t3;
    
    mp_addfast(a[0], a[1], t1);                      // t1 = a0+a1 
    sub_p4(a[0], a[1], t2);                          // t2 = a0-a1
    mp_addfast(a[0], a[0], t3);                      // t3 = 2a0
    fpmul_mont(t1, t2, c[0]);                        // c0 = (a0+a1)(a0-a1)
    fpmul_mont(t3, a[1], c[1]);                      // c1 = 2a0*a1
}


__inline unsigned int mp_sub(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{ // Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit.
    unsigned int i, borrow = 0;

    for (i = 0; i < nwords; i++)
        SUBC(borrow, a[i], b[i], borrow, c[i]);

    return borrow;
}


__inline static void mp_subaddfast(const digit_t* a, const digit_t* b, digit_t* c)
{ // Multiprecision subtraction followed by addition with p*2^MAXBITS_FIELD, c = a-b+(p*2^MAXBITS_FIELD) if a-b < 0, otherwise c=a-b. 
#if (OS_TARGET == OS_WIN) || defined(GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM)
    felm_t t1;

    digit_t mask = 0 - (digit_t)mp_sub(a, b, c, 2*NWORDS_FIELD);
    for (int i = 0; i < NWORDS_FIELD; i++)
        t1[i] = ((digit_t*)PRIME)[i] & mask;
    mp_addfast((digit_t*)&c[NWORDS_FIELD], t1, (digit_t*)&c[NWORDS_FIELD]);

#elif (OS_TARGET == OS_NIX)               

    mp_subaddx2_asm(a, b, c);     

#endif
}


__inline static void mp_dblsubfast(const digit_t* a, const digit_t* b, digit_t* c)
{ // Multiprecision subtraction, c = c-a-b, where lng(a) = lng(b) = 2*NWORDS_FIELD.
#if (OS_TARGET == OS_WIN) || defined(GENERIC_IMPLEMENTATION) || (TARGET == TARGET_ARM)

    mp_sub(c, a, c, 2*NWORDS_FIELD);
    mp_sub(c, b, c, 2*NWORDS_FIELD);

#elif (OS_TARGET == OS_NIX)                 

    mp_dblsubx2_asm(a, b, c);

#endif
}


void fp2mul_mont(const f2elm_t a, const f2elm_t b, f2elm_t c)
{ // GF(p^2) multiplication using Montgomery arithmetic, c = a*b in GF(p^2).
  // Inputs: a = a0+a1*i and b = b0+b1*i, where a0, a1, b0, b1 are in [0, 2*p-1] 
  // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1] 
    felm_t t1, t2;
    dfelm_t tt1, tt2, tt3; 
    
    mp_addfast(a[0], a[1], t1);                      // t1 = a0+a1
    mp_addfast(b[0], b[1], t2);                      // t2 = b0+b1
    mp_mul(a[0], b[0], tt1, NWORDS_FIELD);           // tt1 = a0*b0
    mp_mul(a[1], b[1], tt2, NWORDS_FIELD);           // tt2 = a1*b1
    mp_mul(t1, t2, tt3, NWORDS_FIELD);               // tt3 = (a0+a1)*(b0+b1)
    mp_dblsubfast(tt1, tt2, tt3);                    // tt3 = (a0+a1)*(b0+b1) - a0*b0 - a1*b1
    mp_subaddfast(tt1, tt2, tt1);                    // tt1 = a0*b0 - a1*b1 + p*2^MAXBITS_FIELD if a0*b0 - a1*b1 < 0, else tt1 = a0*b0 - a1*b1
    rdc_mont(tt3, c[1]);                             // c[1] = (a0+a1)*(b0+b1) - a0*b0 - a1*b1 
    rdc_mont(tt1, c[0]);                             // c[0] = a0*b0 - a1*b1
}


void fpinv_chain_mont(felm_t a)
{ // Chain to compute a^(p-3)/4 using Montgomery arithmetic.
    unsigned int i, j;
    
#if (NBITS_FIELD == 434)
    felm_t t[31], tt;

    // Precomputed table
    fpsqr_mont(a, tt);
    fpmul_mont(a, tt, t[0]);
    for (i = 0; i <= 29; i++) fpmul_mont(t[i], tt, t[i+1]);

    fpcopy(a, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[23], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[13], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[24], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[7], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[12], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[30], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[1], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[30], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[21], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[19], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[1], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[24], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[26], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[16], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[20], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[9], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[25], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[30], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[26], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[28], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[22], tt, tt);
    for (j = 0; j < 35; j++) {
        for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
        fpmul_mont(t[30], tt, tt);
    }
    fpcopy(tt, a);   
    
#elif (NBITS_FIELD == 503)
    felm_t t[15], tt;

    // Precomputed table
    fpsqr_mont(a, tt);
    fpmul_mont(a, tt, t[0]);
    for (i = 0; i <= 13; i++) fpmul_mont(t[i], tt, t[i+1]);

    fpcopy(a, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[9], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 12; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[12], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[12], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[4], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[7], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[13], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[1], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (j = 0; j < 49; j++) {
        for (i = 0; i < 5; i++) fpsqr_mont(tt, tt);
        fpmul_mont(t[14], tt, tt);
    }
    fpcopy(tt, a);

#elif (NBITS_FIELD == 610)
    felm_t t[31], tt;

    // Precomputed table
    fpsqr_mont(a, tt);
    fpmul_mont(a, tt, t[0]);
    for (i = 0; i <= 29; i++) fpmul_mont(t[i], tt, t[i+1]);

    fpcopy(a, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[30], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[25], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[28], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[7], tt, tt);
    for (i = 0; i < 11; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[16], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[24], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[28], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[16], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[4], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[20], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[15], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[15], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[19], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[9], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[27], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[28], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[29], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[1], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[30], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[25], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[28], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[22], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[22], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[7], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[9], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[4], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[20], tt, tt);
    for (i = 0; i < 11; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[26], tt, tt);
    for (i = 0; i < 11; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (j = 0; j < 50; j++) {
        for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
        fpmul_mont(t[30], tt, tt);
    }
    fpcopy(tt, a);    

#elif (NBITS_FIELD == 751)
    felm_t t[27], tt;
    
    // Precomputed table
    fpsqr_mont(a, tt);
    fpmul_mont(a, tt, t[0]);
    fpmul_mont(t[0], tt, t[1]);
    fpmul_mont(t[1], tt, t[2]);
    fpmul_mont(t[2], tt, t[3]); 
    fpmul_mont(t[3], tt, t[3]);
    for (i = 3; i <= 8; i++) fpmul_mont(t[i], tt, t[i+1]);
    fpmul_mont(t[9], tt, t[9]);
    for (i = 9; i <= 20; i++) fpmul_mont(t[i], tt, t[i+1]);
    fpmul_mont(t[21], tt, t[21]); 
    for (i = 21; i <= 24; i++) fpmul_mont(t[i], tt, t[i+1]); 
    fpmul_mont(t[25], tt, t[25]);
    fpmul_mont(t[25], tt, t[26]);

    fpcopy(a, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[20], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[24], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[23], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 9; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[15], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[13], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[26], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[20], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[4], tt, tt);
    for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[18], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[1], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[22], tt, tt);
    for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[6], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[24], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[9], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[18], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[17], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(a, tt, tt);
    for (i = 0; i < 10; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[16], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[7], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[0], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[12], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[19], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[22], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[25], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[10], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[22], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[18], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[4], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[14], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[13], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[23], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[21], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[23], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[12], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[9], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[3], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[13], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[17], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[26], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[5], tt, tt);
    for (i = 0; i < 8; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[8], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[2], tt, tt);
    for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[11], tt, tt);
    for (i = 0; i < 7; i++) fpsqr_mont(tt, tt);
    fpmul_mont(t[20], tt, tt);
    for (j = 0; j < 61; j++) {
        for (i = 0; i < 6; i++) fpsqr_mont(tt, tt);
        fpmul_mont(t[26], tt, tt);
    }
    fpcopy(tt, a);  
#endif
}


void fp2inv_mont(f2elm_t a)
{// GF(p^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2).
    f2elm_t t1;

    fpsqr_mont(a[0], t1[0]);                         // t10 = a0^2
    fpsqr_mont(a[1], t1[1]);                         // t11 = a1^2
    fpadd(t1[0], t1[1], t1[0]);                      // t10 = a0^2+a1^2
    fpinv_mont(t1[0]);                               // t10 = (a0^2+a1^2)^-1
    fpneg(a[1]);                                     // a = a0-i*a1
    fpmul_mont(a[0], t1[0], a[0]);
    fpmul_mont(a[1], t1[0], a[1]);                   // a = (a0-i*a1)*(a0^2+a1^2)^-1
}


void to_fp2mont(const f2elm_t a, f2elm_t mc)
{ // Conversion of a GF(p^2) element to Montgomery representation,
  // mc_i = a_i*R^2*R^(-1) = a_i*R in GF(p^2). 

    to_mont(a[0], mc[0]);
    to_mont(a[1], mc[1]);
}


void from_fp2mont(const f2elm_t ma, f2elm_t c)
{ // Conversion of a GF(p^2) element from Montgomery representation to standard representation,
  // c_i = ma_i*R^(-1) = a_i in GF(p^2).

    from_mont(ma[0], c[0]);
    from_mont(ma[1], c[1]);
}


void mp_shiftleft(digit_t* x, unsigned int shift, const unsigned int nwords)
{
    unsigned int i, j = 0;

    while (shift > RADIX) {
        j += 1;
        shift -= RADIX;
    }

    for (i = 0; i < nwords-j; i++) 
        x[nwords-1-i] = x[nwords-1-i-j];
    for (i = nwords-j; i < nwords; i++) 
        x[nwords-1-i] = 0;
    if (shift != 0) {
        for (j = nwords-1; j > 0; j--) 
            SHIFTL(x[j], x[j-1], shift, x[j], RADIX);
        x[0] <<= shift;
    }
}


void mp_shiftr1(digit_t* x, const unsigned int nwords)
{ // Multiprecision right shift by one.
    unsigned int i;

    for (i = 0; i < nwords-1; i++) {
        SHIFTR(x[i+1], x[i], 1, x[i], RADIX);
    }
    x[nwords-1] >>= 1;
}


void mp_shiftl1(digit_t* x, const unsigned int nwords)
{ // Multiprecision left shift by one.
    int i;

    for (i = nwords-1; i > 0; i--) {
        SHIFTL(x[i], x[i-1], 1, x[i], RADIX);
    }
    x[0] <<= 1;
}

#ifdef COMPRESS

static __inline unsigned int is_felm_zero(const felm_t x)
{ // Is x = 0? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
  // SECURITY NOTE: This function does not run in constant-time.
    unsigned int i;

    for (i = 0; i < NWORDS_FIELD; i++) {
        if (x[i] != 0) return 0;
    }
    return 1;
}

static __inline unsigned int is_felm_one(const felm_t x)
{ // Is x = 0? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
  // SECURITY NOTE: This function does not run in constant-time.
    unsigned int i;

    for (i = 0; i < NWORDS_FIELD; i++) {
        if (x[i] != 0) return 0;
    }
    return 1;
}

void mul3(unsigned char *a) 
{ // Computes a = 3*a
  // The input is assumed to be OBOB_BITS-2 bits long and stored in SECRETKEY_B_BYTES
    digit_t temp1[NWORDS_ORDER] = {0}, temp2[NWORDS_ORDER] = {0};
        
    decode_to_digits(a, temp1, SECRETKEY_B_BYTES, NWORDS_ORDER);
    mp_add(temp1, temp1, temp2, NWORDS_ORDER);               // temp2 = 2*a
    mp_add(temp1, temp2, temp1, NWORDS_ORDER);               // temp1 = 3*a
    encode_to_bytes(temp1, a, SECRETKEY_B_BYTES);
    
    clear_words((void*)temp1, NWORDS_ORDER);
    clear_words((void*)temp2, NWORDS_ORDER);
}


unsigned int mod3(digit_t* a) 
{ // Computes the input modulo 3
  // The input is assumed to be NWORDS_ORDER long 
    digit_t temp;
    hdigit_t *val = (hdigit_t*)a, r = 0;

    for (int i = (2*NWORDS_ORDER-1); i >= 0; i--) {
        temp = ((digit_t)r << (sizeof(hdigit_t)*8)) | (digit_t)val[i];
        r = temp % 3;
    }

    return r;
}


void fp2shl(const f2elm_t a, const int k, f2elm_t c) 
{  // c = (2^k)*a
   fp2copy(a, c);
   for (int j = 0; j < k; j++) {
      fp2add(c, c, c);
   }
}


void fp2_conj(const f2elm_t v, f2elm_t r)
{ // r = a - b*i where v = a + b*i
    fpcopy(v[0],r[0]);
    fpcopy(v[1],r[1]);
    
    if(!is_felm_zero(r[1])) {
        fpneg(r[1]);
    }
}


void sqr_Fp2_cycl(f2elm_t a, const felm_t one)
{ // Cyclotomic squaring on elements of norm 1, using a^(p+1) = 1.
     felm_t t0;
 
     fpadd(a[0], a[1], t0);              // t0 = a0 + a1
     fpsqr_mont(t0, t0);                 // t0 = t0^2
     fpsub(t0, one, a[1]);               // a1 = t0 - 1   
     fpsqr_mont(a[0], t0);               // t0 = a0^2
     fpadd(t0, t0, t0);                  // t0 = t0 + t0
     fpsub(t0, one, a[0]);               // a0 = t0 - 1
}


void cube_Fp2_cycl(f2elm_t a, const felm_t one)
{ // Cyclotomic cubing on elements of norm 1, using a^(p+1) = 1.
     felm_t t0;
   
     fpadd(a[0], a[0], t0);              // t0 = a0 + a0
     fpsqr_mont(t0, t0);                 // t0 = t0^2
     fpsub(t0, one, t0);                 // t0 = t0 - 1
     fpmul_mont(a[1], t0, a[1]);         // a1 = t0*a1
     fpsub(t0, one, t0);
     fpsub(t0, one, t0);                 // t0 = t0 - 2
     fpmul_mont(a[0], t0, a[0]);         // a0 = t0*a0
}






static bool is_zero(digit_t* a, unsigned int nwords)
{ // Check if multiprecision element is zero.
  // SECURITY NOTE: This function does not run in constant time.

    for (unsigned int i = 0; i < nwords; i++) {
        if (a[i] != 0) {
            return false;
        } 
    }

    return true;
}


unsigned char is_sqr_fp2(const f2elm_t a, felm_t s) 
{ // Test if a is a square in GF(p^2) and return 1 if true, 0 otherwise
  // If a is a quadratic residue, s will be assigned with a partially computed square root of a
    int i;
    felm_t a0,a1,z,temp;
    
    fpsqr_mont(a[0],a0);
    fpsqr_mont(a[1],a1);
    fpadd(a0,a1,z);
    
    fpcopy(z,s);
    for (i = 0; i < OALICE_BITS - 2; i++) {             
        fpsqr_mont(s, s);
    }
    for (i = 0; i < OBOB_EXPON; i++) {
        fpsqr_mont(s, temp);
        fpmul_mont(s, temp, s);
    }  
    fpsqr_mont(s,temp);          // s = z^((p+1)/4)
    fpcorrection(temp);
    fpcorrection(z);
    if (memcmp((unsigned char*)temp, (unsigned char*)z, NBITS_TO_NBYTES(NBITS_FIELD)) != 0)  // s^2 !=? z
        return 0;
    
    return 1;
}


void sqrt_Fp2(const f2elm_t u, f2elm_t y)
{ // Computes square roots of elements in (Fp2)^2 using Hamburg's trick. 
    felm_t t0, t1, t2, t3;
    digit_t *a  = (digit_t*)u[0], *b  = (digit_t*)u[1];
    unsigned int i;

    fpsqr_mont(a, t0);                   // t0 = a^2
    fpsqr_mont(b, t1);                   // t1 = b^2
    fpadd(t0, t1, t0);                   // t0 = t0+t1 
    fpcopy(t0, t1);
    for (i = 0; i < OALICE_BITS - 2; i++) {   // t = t3^((p+1)/4)
        fpsqr_mont(t1, t1);
    }
    for (i = 0; i < OBOB_EXPON; i++) {
        fpsqr_mont(t1, t0);
        fpmul_mont(t1, t0, t1);
    }  
    fpadd(a, t1, t0);                    // t0 = a+t1      
    fpdiv2(t0, t0);                      // t0 = t0/2 
    fpcopy(t0, t2);
    fpinv_chain_mont(t2);                // t2 = t0^((p-3)/4)      
    fpmul_mont(t0, t2, t1);              // t1 = t2*t0             
    fpmul_mont(t2, b, t2);               // t2 = t2*b       
    fpdiv2(t2, t2);                      // t2 = t2/2 
    fpsqr_mont(t1, t3);                  // t3 = t1^2              
    fpcorrection(t0);
    fpcorrection(t3);
           
    if (memcmp(t0, t3, NBITS_TO_NBYTES(NBITS_FIELD)) == 0) {
        fpcopy(t1, y[0]);
        fpcopy(t2, y[1]);
    } else {
        fpneg(t1);
        fpcopy(t2, y[0]);
        fpcopy(t1, y[1]);
    }
}


static __inline void power2_setup(digit_t* x, int mark, const unsigned int nwords)
{ // Set up the value 2^mark.
    unsigned int i;

    for (i = 0; i < nwords; i++) x[i] = 0;

    i = 0;
    while (mark >= 0) {
        if (mark < RADIX) {
            x[i] = (digit_t)1 << mark;
        }
        mark -= RADIX;
        i += 1;
    }    
}


int8_t cmp_f2elm(const f2elm_t x, const f2elm_t y)
{ // Comparison of two GF(p^2) elements in constant time. 
  // Is x != y? return -1 if condition is true, 0 otherwise.
    f2elm_t a, b;      
    uint8_t r = 0;
    
    fp2copy(x, a);
    fp2copy(y, b);
    fp2correction(a);
    fp2correction(b);
    
    for (int i = NWORDS_FIELD-1; i >= 0; i--)
        r |= (a[0][i] ^ b[0][i]) | (a[1][i] ^ b[1][i]);

    return (-(int8_t)r) >> (8*sizeof(uint8_t)-1);
}


static __inline unsigned int is_felm_even(const felm_t x)
{ // Is x even? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
    return (unsigned int)((x[0] & 1) ^ 1);
}


static __inline unsigned int is_felm_lt(const felm_t x, const felm_t y)
{ // Is x < y? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
  // SECURITY NOTE: This function does not run in constant-time.

    for (int i = NWORDS_FIELD-1; i >= 0; i--) {
        if (x[i] < y[i]) { 
            return true;
        } else if (x[i] > y[i]) {
            return false;
        }
    }
    return false;
}


static __inline unsigned int is_orderelm_lt(const digit_t *x, const digit_t *y)
{ // Is x < y? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
  // SECURITY NOTE: This function does not run in constant-time.

    for (int i = NWORDS_ORDER-1; i >= 0; i--) {
        if (x[i] < y[i]) { 
            return true;
        } else if (x[i] > y[i]) {
            return false;
        }
    }
    return false;
}


static __inline void fpinv_mont_bingcd_partial(const felm_t a, felm_t x1, unsigned int* k)
{ // Partial Montgomery inversion via the binary GCD algorithm.
    felm_t u, v, x2;
    unsigned int cwords;  // Number of words necessary for x1, x2

    fpcopy(a, u);
    fpcopy((digit_t*)PRIME, v);
    fpzero(x1); x1[0] = 1;
    fpzero(x2);
    *k = 0;

    while (!is_felm_zero(v)) {
        cwords = ((*k + 1) / RADIX) + 1;
        if ((cwords < NWORDS_FIELD)) {
            if (is_felm_even(v)) {
                mp_shiftr1(v, NWORDS_FIELD);
                mp_shiftl1(x1, cwords);
            } else if (is_felm_even(u)) {
                mp_shiftr1(u, NWORDS_FIELD);
                mp_shiftl1(x2, cwords);
            } else if (!is_felm_lt(v, u)) {
                mp_sub(v, u, v, NWORDS_FIELD);
                mp_shiftr1(v, NWORDS_FIELD);
                mp_add(x1, x2, x2, cwords);
                mp_shiftl1(x1, cwords);
            } else {
                mp_sub(u, v, u, NWORDS_FIELD);
                mp_shiftr1(u, NWORDS_FIELD);
                mp_add(x1, x2, x1, cwords);
                mp_shiftl1(x2, cwords);
            }
        } else {
            if (is_felm_even(v)) {
                mp_shiftr1(v, NWORDS_FIELD);
                mp_shiftl1(x1, NWORDS_FIELD);
            } else if (is_felm_even(u)) {
                mp_shiftr1(u, NWORDS_FIELD);
                mp_shiftl1(x2, NWORDS_FIELD);
            } else if (!is_felm_lt(v, u)) {
                mp_sub(v, u, v, NWORDS_FIELD);
                mp_shiftr1(v, NWORDS_FIELD);
                mp_add(x1, x2, x2, NWORDS_FIELD);
                mp_shiftl1(x1, NWORDS_FIELD);
            } else {
                mp_sub(u, v, u, NWORDS_FIELD);
                mp_shiftr1(u, NWORDS_FIELD);
                mp_add(x1, x2, x1, NWORDS_FIELD);
                mp_shiftl1(x2, NWORDS_FIELD);
            }
        }
        *k += 1;
    }

    if (is_felm_lt((digit_t*)PRIME, x1)) {
        mp_sub(x1, (digit_t*)PRIME, x1, NWORDS_FIELD);
    }
}


void fpinv_mont_bingcd(felm_t a)
{ // Field inversion via the binary GCD using Montgomery arithmetic, a = a^-1*r' mod p.
  // SECURITY NOTE: This function does not run in constant-time and is therefore only suitable for 
  //                operations not involving any secret data.
    felm_t x, t;
    unsigned int k;

    if (is_felm_zero(a) == true)
        return;

    fpinv_mont_bingcd_partial(a, x, &k);
    if (k <= MAXBITS_FIELD) { 
        fpmul_mont(x, (digit_t*)&Montgomery_R2, x);
        k += MAXBITS_FIELD;
    }
    fpmul_mont(x, (digit_t*)&Montgomery_R2, x);
    power2_setup(t, 2*MAXBITS_FIELD - k, NWORDS_FIELD);
    fpmul_mont(x, t, a);
}


void fp2inv_mont_bingcd(f2elm_t a)
{// GF(p^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2)
 // This uses the binary GCD for inversion in fp and is NOT constant time!!!
    f2elm_t t1;

    fpsqr_mont(a[0], t1[0]);             // t10 = a0^2
    fpsqr_mont(a[1], t1[1]);             // t11 = a1^2
    fpadd(t1[0], t1[1], t1[0]);          // t10 = a0^2+a1^2
    fpinv_mont_bingcd(t1[0]);            // t10 = (a0^2+a1^2)^-1
    fpneg(a[1]);                         // a = a0-i*a1
    fpmul_mont(a[0], t1[0], a[0]);
    fpmul_mont(a[1], t1[0], a[1]);       // a = (a0-i*a1)*(a0^2+a1^2)^-1
}


void mont_n_way_inv(const f2elm_t* vec, const int n, f2elm_t* out)
{ // n-way simultaneous inversion using Montgomery's trick.
  // SECURITY NOTE: This function does not run in constant time.
  // Also, vec and out CANNOT be the same variable!
    f2elm_t t1;
    int i;

    fp2copy(vec[0], out[0]);                      // out[0] = vec[0]
    for (i = 1; i < n; i++) {
        fp2mul_mont(out[i-1], vec[i], out[i]);    // out[i] = out[i-1]*vec[i]
    }

    fp2copy(out[n-1], t1);                        // t1 = 1/out[n-1]
    fp2inv_mont_bingcd(t1);
    
    for (i = n-1; i >= 1; i--) {
        fp2mul_mont(out[i-1], t1, out[i]);        // out[i] = t1*out[i-1]
        fp2mul_mont(t1, vec[i], t1);              // t1 = t1*vec[i]
    }
    fp2copy(t1, out[0]);                          // out[0] = t1
}


void multiply(const digit_t* a, const digit_t* b, digit_t* c, const unsigned int nwords)
{ // Multiprecision comba multiply, c = a*b, where lng(a) = lng(b) = nwords.
  // NOTE: a and c CANNOT be the same variable!
    unsigned int i, j, carry = 0;
    digit_t t = 0, u = 0, v = 0, UV[2];
    
    for (i = 0; i < nwords; i++) {
        for (j = 0; j <= i; j++) {
            MUL(a[j], b[i-j], UV+1, UV[0]);
            ADDC(0, UV[0], v, carry, v);
            ADDC(carry, UV[1], u, carry, u);
            t += carry;
        }
        c[i] = v;
        v = u;
        u = t;
        t = 0;
    }
    for (i = nwords; i < 2*nwords-1; i++) {
        for (j = i-nwords+1; j < nwords; j++) {
            MUL(a[j], b[i-j], UV+1, UV[0]);
            ADDC(0, UV[0], v, carry, v);
            ADDC(carry, UV[1], u, carry, u);
            t += carry;
        }
        c[i] = v;
        v = u;
        u = t;
        t = 0;
    }
    c[2*nwords-1] = v;
}


void Montgomery_neg(digit_t* a, digit_t* order)
{ // Modular negation, a = -a mod p.
  // Input/output: a in [0, 2*p-1] 
    unsigned int i, borrow = 0;
    
    for (i = 0; i < NWORDS_ORDER; i++) {
        SUBC(borrow, order[i], a[i], borrow, a[i]);
    }
}


void Montgomery_multiply_mod_order(const digit_t* ma, const digit_t* mb, digit_t* mc, const digit_t* order, const digit_t* Montgomery_rprime)
{ // Montgomery multiplication modulo the group order, mc = ma*mb*r' mod order, where ma,mb,mc in [0, order-1].
  // ma, mb and mc are assumed to be in Montgomery representation.
  // The Montgomery constant r' = -r^(-1) mod 2^(log_2(r)) is the value "Montgomery_rprime", where r is the order.  
  // Assume log_2(r) is a multiple of RADIX bits
    unsigned int i, cout = 0, bout = 0;
    digit_t mask, P[2*NWORDS_ORDER] = {0}, Q[2*NWORDS_ORDER] = {0}, temp[2*NWORDS_ORDER] = {0};

    multiply(ma, mb, P, NWORDS_ORDER);                 // P = ma * mb
    multiply(P, Montgomery_rprime, Q, NWORDS_ORDER);   // Q = P * r' mod 2^(log_2(r))
    multiply(Q, order, temp, NWORDS_ORDER);            // temp = Q * r
    cout = mp_add(P, temp, temp, 2*NWORDS_ORDER);      // (cout, temp) = P + Q * r     

    for (i = 0; i < NWORDS_ORDER; i++) {               // (cout, mc) = (P + Q * r)/2^(log_2(r))
        mc[i] = temp[NWORDS_ORDER+i];
    }

    // Final, constant-time subtraction     
    bout = mp_sub(mc, order, mc, NWORDS_ORDER);        // (cout, mc) = (cout, mc) - r
    mask = (digit_t)cout - (digit_t)bout;              // if (cout, mc) >= 0 then mask = 0x00..0, else if (cout, mc) < 0 then mask = 0xFF..F
    
    for (i = 0; i < NWORDS_ORDER; i++) {               // temp = mask & r
        temp[i] = (order[i] & mask);
    }
    
    mp_add(mc, temp, mc, NWORDS_ORDER);                //  mc = mc + (mask & r)
}


void to_Montgomery_mod_order(const digit_t* a, digit_t* mc, const digit_t* order, const digit_t* Montgomery_rprime, const digit_t* Montgomery_Rprime)
{ // Conversion of elements in Z_r to Montgomery representation, where the order r is up to NBITS_ORDER bits.
    Montgomery_multiply_mod_order(a, Montgomery_Rprime, mc, order, Montgomery_rprime);
}


void from_Montgomery_mod_order(const digit_t* ma, digit_t* c, const digit_t* order, const digit_t* Montgomery_rprime)
{ // Conversion of elements in Z_r from Montgomery to standard representation, where the order is up to NBITS_ORDER bits.
    digit_t one[NWORDS_ORDER] = {0};
    one[0] = 1;

    Montgomery_multiply_mod_order(ma, one, c, order, Montgomery_rprime);
}


static __inline unsigned int is_zero_mod_order(const digit_t* x)
{ // Is x = 0? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise
  // SECURITY NOTE: This function does not run in constant time.
    unsigned int i;

    for (i = 0; i < NWORDS_ORDER; i++) {
        if (x[i] != 0) return false;
    }
    return true;
}


static __inline unsigned int is_even_mod_order(const digit_t* x)
{ // Is x even? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
    return (unsigned int)((x[0] & 1) ^ 1);
}


static __inline unsigned int is_lt_mod_order(const digit_t* x, const digit_t* y)
{ // Is x < y? return 1 (TRUE) if condition is true, 0 (FALSE) otherwise.
  // SECURITY NOTE: This function does not run in constant time.
    int i;

    for (i = NWORDS_ORDER-1; i >= 0; i--) {
        if (x[i] < y[i]) { 
            return true;
        } else if (x[i] > y[i]) {
            return false;
        }
    }
    return false;
}


static __inline void Montgomery_inversion_mod_order_bingcd_partial(const digit_t* a, digit_t* x1, unsigned int* k, const digit_t* order)
{ // Partial Montgomery inversion modulo order.
    digit_t u[NWORDS_ORDER], v[NWORDS_ORDER], x2[NWORDS_ORDER] = {0};
    unsigned int cwords;  // number of words necessary for x1, x2

    copy_words(a, u, NWORDS_ORDER);
    copy_words(order, v, NWORDS_ORDER);
    copy_words(x2, x1, NWORDS_ORDER);
    x1[0] = 1;
    *k = 0;

    while (!is_zero_mod_order(v)) {
        cwords = ((*k + 1) / RADIX) + 1;
        if ((cwords < NWORDS_ORDER)) {
            if (is_even_mod_order(v)) {
                mp_shiftr1(v, NWORDS_ORDER);
                mp_shiftl1(x1, cwords);
            } else if (is_even_mod_order(u)) {
                mp_shiftr1(u, NWORDS_ORDER);
                mp_shiftl1(x2, cwords);
            } else if (!is_lt_mod_order(v, u)) {
                mp_sub(v, u, v, NWORDS_ORDER);
                mp_shiftr1(v, NWORDS_ORDER);
                mp_add(x1, x2, x2, cwords);
                mp_shiftl1(x1, cwords);
            } else {
                mp_sub(u, v, u, NWORDS_ORDER);
                mp_shiftr1(u, NWORDS_ORDER);
                mp_add(x1, x2, x1, cwords);
                mp_shiftl1(x2, cwords);
            }
        } else {
            if (is_even_mod_order(v)) {
                mp_shiftr1(v, NWORDS_ORDER);
                mp_shiftl1(x1, NWORDS_ORDER);
            } else if (is_even_mod_order(u)) {
                mp_shiftr1(u, NWORDS_ORDER);
                mp_shiftl1(x2, NWORDS_ORDER);
            } else if (!is_lt_mod_order(v, u)) {
                mp_sub(v, u, v, NWORDS_ORDER);
                mp_shiftr1(v, NWORDS_ORDER);
                mp_add(x1, x2, x2, NWORDS_ORDER);
                mp_shiftl1(x1, NWORDS_ORDER);
            } else {
                mp_sub(u, v, u, NWORDS_ORDER);
                mp_shiftr1(u, NWORDS_ORDER);
                mp_add(x1, x2, x1, NWORDS_ORDER);
                mp_shiftl1(x2, NWORDS_ORDER);
            }
        }
        *k += 1;
    }

    if (is_lt_mod_order(order, x1)) {
        mp_sub(x1, order, x1, NWORDS_ORDER);
    }
}


void Montgomery_inversion_mod_order_bingcd(const digit_t* a, digit_t* c, const digit_t* order, const digit_t* Montgomery_rprime, const digit_t* Montgomery_Rprime)
{// Montgomery inversion modulo order, c = a^(-1)*R mod order.
    digit_t x[NWORDS_ORDER], t[NWORDS_ORDER] = {0};
    unsigned int k;

    if (is_zero((digit_t*)a, NWORDS_ORDER) == true) {
        copy_words(t, c, NWORDS_ORDER);
        return;
    }

    Montgomery_inversion_mod_order_bingcd_partial(a, x, &k, order);
    if (k <= NBITS_ORDER) {
        Montgomery_multiply_mod_order(x, Montgomery_Rprime, x, order, Montgomery_rprime);
        k += NBITS_ORDER;
    }

    Montgomery_multiply_mod_order(x, Montgomery_Rprime, x, order, Montgomery_rprime);
    power2_setup(t, 2*NBITS_ORDER - k, NWORDS_ORDER);
    Montgomery_multiply_mod_order(x, t, c, order, Montgomery_rprime);
}


void inv_mod_orderA(const digit_t* a, digit_t* c)
{ // Inversion of an odd integer modulo an even integer of the form 2^m.
  // Algorithm 3: Explicit Quadratic Modular inverse modulo 2^m from Dumas'12: http://arxiv.org/pdf/1209.6626.pdf
  // If the input is invalid (even), the function outputs c = a.
    unsigned int i, f, s = 0;
    digit_t am1[NWORDS_ORDER] = {0};
    digit_t tmp1[NWORDS_ORDER] = {0};
    digit_t tmp2[2*NWORDS_ORDER] = {0};
    digit_t one[NWORDS_ORDER] = {0};
    digit_t order[NWORDS_ORDER] = {0};
    digit_t mask = (digit_t)((uint64_t)(-1) >> (NBITS_ORDER - OALICE_BITS));

    order[NWORDS_ORDER-1] = (digit_t)((uint64_t)1 << (64 - (NBITS_ORDER - OALICE_BITS)));  // Load most significant digit of Alice's order
    one[0] = 1;
        
    mp_sub(a, one, am1, NWORDS_ORDER);                   // am1 = a-1

    if (((a[0] & (digit_t)1) == 0) || (is_zero(am1, NWORDS_ORDER) == true)) {  // Check if the input is even or one 
        copy_words(a, c, NWORDS_ORDER);
        c[NWORDS_ORDER-1] &= mask;                       // mod 2^m
    } else { 
        mp_sub(order, am1, c, NWORDS_ORDER);
        mp_add(c, one, c, NWORDS_ORDER);                 // c = 2^m - a + 2

        copy_words(am1, tmp1, NWORDS_ORDER);
        while ((tmp1[0] & (digit_t)1) == 0) {
            s += 1;
            mp_shiftr1(tmp1, NWORDS_ORDER);
        }

        f = OALICE_BITS / s;
        for (i = 1; i < f; i <<= 1) {
            multiply(am1, am1, tmp2, NWORDS_ORDER);            // tmp2 = am1^2  
            copy_words(tmp2, am1, NWORDS_ORDER);
            am1[NWORDS_ORDER-1] &= mask;                       // am1 = tmp2 mod 2^m
            mp_add(am1, one, tmp1, NWORDS_ORDER);              // tmp1 = am1 + 1
            tmp1[NWORDS_ORDER-1] &= mask;                      // mod 2^m
            multiply(c, tmp1, tmp2, NWORDS_ORDER);             // c = c*tmp1
            copy_words(tmp2, c, NWORDS_ORDER);
            c[NWORDS_ORDER-1] &= mask;                         // mod 2^m
        }
    }
}


void recover_os(const f2elm_t X1, const f2elm_t Z1, const f2elm_t X2, const f2elm_t Z2, const f2elm_t x, const f2elm_t y, const f2elm_t A, f2elm_t X3, f2elm_t Y3, f2elm_t Z3)
{
    f2elm_t t0, t1, t2, t3;
    
    // X3 := 2*y*Z1*Z2*X1;
    // Y3 := Z2*((X1+x*Z1+2*A*Z1)*(X1*x+Z1)-2*A*Z1^2)-(X1-x*Z1)^2*X2;
    // Z3 := 2*y*Z1*Z2*Z1;
    
    fp2add(y, y, t0);
    fp2mul_mont(t0, Z1, t0);
    fp2mul_mont(t0, Z2, t0);       // t0 = 2*y*Z1*Z2
    fp2mul_mont(t0, Z1, Z3);       // Z3 = 2*y*Z1*Z2*Z1       
    fp2mul_mont(t0, X1, X3);       // X3 = 2*y*Z1*Z2*X1
    fp2add(A, A, t0);
    fp2mul_mont(t0, Z1, t0);       // t0 = 2*A*Z1  
    fp2mul_mont(x, Z1, t1);        // t1 = x*Z1  
    fp2add(X1, t1, t2);            // t2 = X1+x*Z1
    fp2sub(X1, t1, t1);            // t1 = X1-x*Z1
    fp2add(t0, t2, t3);            // t3 = X1+x*Z1+2*A*Z1
    fp2mul_mont(t0, Z1, t0);       // t0 = 2*A*Z1^2 
    fp2sqr_mont(t1, t1);           // t1 = (X1-x*Z1)^2
    fp2mul_mont(x, X1, t2);        // t2 = x*X1
    fp2add(t2, Z1, t2);            // t2 = X1*x+Z1
    fp2mul_mont(t2, t3, t2);       // t2 = (X1+x*Z1+2*A*Z1)*(X1*x+Z1)
    fp2sub(t2, t0, t0);            // t0 = (X1+x*Z1+2*A*Z1)*(X1*x+Z1)-2*A*Z1^2
    fp2mul_mont(t1, X2, t1);       // t1 = (X1-x*Z1)^2*X2
    fp2mul_mont(t0, Z2, t0);       // t0 = Z2*[(X1+x*Z1+2*A*Z1)*(X1*x+Z1)-2*A*Z1^2]
    fp2sub(t0, t1, Y3);            // Y3 = Z2*[(X1+x*Z1+2*A*Z1)*(X1*x+Z1)-2*A*Z1^2] - (X1-x*Z1)^2*X2
}
// Closing COMPRESSED
#endif