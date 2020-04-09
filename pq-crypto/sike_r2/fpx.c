/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: core functions over GF(p) and GF(p^2)
*********************************************************************************************/

void fp2_encode(const f2elm_t *x, unsigned char *enc) { // Conversion of GF(p^2) element from Montgomery to standard representation, and encoding by removing leading 0 bytes
	unsigned int i;
	f2elm_t t;

	from_fp2mont(x, &t);
	for (i = 0; i < FP2_ENCODED_BYTES / 2; i++) {
		enc[i] = ((unsigned char *) t.e)[i];
		enc[i + FP2_ENCODED_BYTES / 2] = ((unsigned char *) t.e)[i + MAXBITS_FIELD / 8];
	}
}

void fp2_decode(const unsigned char *enc, f2elm_t *x) { // Parse byte sequence back into GF(p^2) element, and conversion to Montgomery representation
	unsigned int i;

	for (i = 0; i < 2 * (MAXBITS_FIELD / 8); i++)
		((unsigned char *) x->e)[i] = 0;
	for (i = 0; i < FP2_ENCODED_BYTES / 2; i++) {
		((unsigned char *) x->e)[i] = enc[i];
		((unsigned char *) x->e)[i + MAXBITS_FIELD / 8] = enc[i + FP2_ENCODED_BYTES / 2];
	}
	to_fp2mont(x, x);
}

__inline void fpcopy(const felm_t a, felm_t c) { // Copy a field element, c = a.
	unsigned int i;

	for (i = 0; i < NWORDS_FIELD; i++)
		c[i] = a[i];
}

__inline void fpzero(felm_t a) { // Zero a field element, a = 0.
	unsigned int i;

	for (i = 0; i < NWORDS_FIELD; i++)
		a[i] = 0;
}

void to_mont(const felm_t a, felm_t mc) { // Conversion to Montgomery representation,
	                                             // mc = a*R^2*R^(-1) mod p = a*R mod p, where a in [0, p-1].
	                                             // The Montgomery constant R^2 mod p is the global value "Montgomery_R2".

	fpmul_mont(a, (const digit_t *) &Montgomery_R2, mc);
}

void from_mont(const felm_t ma, felm_t c) { // Conversion from Montgomery representation to standard representation,
	                                               // c = ma*R^(-1) mod p = a mod p, where ma in [0, p-1].
	digit_t one[NWORDS_FIELD] = {0};

	one[0] = 1;
	fpmul_mont(ma, one, c);
	fpcorrection(c);
}

void copy_words(const digit_t *a, digit_t *c, const unsigned int nwords) { // Copy wordsize digits, c = a, where lng(a) = nwords.
	unsigned int i;

	for (i = 0; i < nwords; i++)
		c[i] = a[i];
}

void fpmul_mont(const felm_t ma, const felm_t mb, felm_t mc) { // Multiprecision multiplication, c = a*b mod p.
	dfelm_t temp = {0};

	mp_mul(ma, mb, temp, NWORDS_FIELD);
	rdc_mont(temp, mc);
}

void fpsqr_mont(const felm_t ma, felm_t mc) { // Multiprecision squaring, c = a^2 mod p.
	dfelm_t temp = {0};

	mp_mul(ma, ma, temp, NWORDS_FIELD);
	rdc_mont(temp, mc);
}

void fpinv_mont(felm_t a) { // Field inversion using Montgomery arithmetic, a = a^(-1)*R mod p.
	felm_t tt;

	fpcopy(a, tt);
	fpinv_chain_mont(tt);
	fpsqr_mont(tt, tt);
	fpsqr_mont(tt, tt);
	fpmul_mont(a, tt, a);
}

void fp2copy(const f2elm_t *a, f2elm_t *c) { // Copy a GF(p^2) element, c = a.
	fpcopy(a->e[0], c->e[0]);
	fpcopy(a->e[1], c->e[1]);
}

void fp2zero(f2elm_t *a) { // Zero a GF(p^2) element, a = 0.
	fpzero(a->e[0]);
	fpzero(a->e[1]);
}

void fp2neg(f2elm_t *a) { // GF(p^2) negation, a = -a in GF(p^2).
	fpneg(a->e[0]);
	fpneg(a->e[1]);
}

__inline void fp2add(const f2elm_t *a, const f2elm_t *b, f2elm_t *c) { // GF(p^2) addition, c = a+b in GF(p^2).
	fpadd(a->e[0], b->e[0], c->e[0]);
	fpadd(a->e[1], b->e[1], c->e[1]);
}

__inline void fp2sub(const f2elm_t *a, const f2elm_t *b, f2elm_t *c) { // GF(p^2) subtraction, c = a-b in GF(p^2).
	fpsub(a->e[0], b->e[0], c->e[0]);
	fpsub(a->e[1], b->e[1], c->e[1]);
}

void fp2div2(const f2elm_t *a, f2elm_t *c) { // GF(p^2) division by two, c = a/2  in GF(p^2).
	fpdiv2(a->e[0], c->e[0]);
	fpdiv2(a->e[1], c->e[1]);
}

void fp2correction(f2elm_t *a) { // Modular correction, a = a in GF(p^2).
	fpcorrection(a->e[0]);
	fpcorrection(a->e[1]);
}

__inline static void mp_addfast(const digit_t *a, const digit_t *b, digit_t *c) { // Multiprecision addition, c = a+b.
#if (OS_TARGET == OS_WIN) || defined(S2N_PQ_GENERIC) || (TARGET == TARGET_ARM) || (TARGET == TARGET_ARM64 && (NBITS_FIELD == 434 || NBITS_FIELD == 610))

	mp_add(a, b, c, NWORDS_FIELD);

#elif (OS_TARGET == OS_LINUX)

	mp_add_asm(a, b, c);

#endif
}

void fp2sqr_mont(const f2elm_t *a, f2elm_t *c) { // GF(p^2) squaring using Montgomery arithmetic, c = a^2 in GF(p^2).
	                                                  // Inputs: a = a0+a1*i, where a0, a1 are in [0, 2*p-1]
	                                                  // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1]
	felm_t t1, t2, t3;

	mp_addfast(a->e[0], a->e[1], t1); // t1 = a0+a1
	fpsub(a->e[0], a->e[1], t2);      // t2 = a0-a1
	mp_addfast(a->e[0], a->e[0], t3); // t3 = 2a0
	fpmul_mont(t1, t2, c->e[0]);   // c0 = (a0+a1)(a0-a1)
	fpmul_mont(t3, a->e[1], c->e[1]); // c1 = 2a0*a1
}

unsigned int mp_sub(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords) { // Multiprecision subtraction, c = a-b, where lng(a) = lng(b) = nwords. Returns the borrow bit.
	unsigned int i, borrow = 0;

	for (i = 0; i < nwords; i++)
		SUBC(borrow, a[i], b[i], borrow, c[i]);

	return borrow;
}

__inline static void mp_subaddfast(const digit_t *a, const digit_t *b, digit_t *c) { // Multiprecision subtraction followed by addition with p*2^MAXBITS_FIELD, c = a-b+(p*2^MAXBITS_FIELD) if a-b < 0, otherwise c=a-b.
#if (OS_TARGET == OS_WIN) || defined(S2N_PQ_GENERIC) || (TARGET == TARGET_ARM) || (TARGET == TARGET_ARM64 && (NBITS_FIELD == 434 || NBITS_FIELD == 610))
	felm_t t1;

	digit_t mask = 0 - (digit_t) mp_sub(a, b, c, 2 * NWORDS_FIELD);
	for (int i = 0; i < NWORDS_FIELD; i++)
		t1[i] = ((const digit_t *) PRIME)[i] & mask;
	mp_addfast((digit_t *) &c[NWORDS_FIELD], t1, (digit_t *) &c[NWORDS_FIELD]);

#elif (OS_TARGET == OS_LINUX)

	mp_subaddx2_asm(a, b, c);

#endif
}

__inline static void mp_dblsubfast(const digit_t *a, const digit_t *b, digit_t *c) { // Multiprecision subtraction, c = c-a-b, where lng(a) = lng(b) = 2*NWORDS_FIELD.
#if (OS_TARGET == OS_WIN) || defined(S2N_PQ_GENERIC) || (TARGET == TARGET_ARM) || (TARGET == TARGET_ARM64 && (NBITS_FIELD == 434 || NBITS_FIELD == 610))

	mp_sub(c, a, c, 2 * NWORDS_FIELD);
	mp_sub(c, b, c, 2 * NWORDS_FIELD);

#elif (OS_TARGET == OS_LINUX)

	mp_dblsubx2_asm(a, b, c);

#endif
}

void fp2mul_mont(const f2elm_t *a, const f2elm_t *b, f2elm_t *c) { // GF(p^2) multiplication using Montgomery arithmetic, c = a*b in GF(p^2).
	                                                                   // Inputs: a = a0+a1*i and b = b0+b1*i, where a0, a1, b0, b1 are in [0, 2*p-1]
	                                                                   // Output: c = c0+c1*i, where c0, c1 are in [0, 2*p-1]
	felm_t t1, t2;
	dfelm_t tt1, tt2, tt3;

	mp_addfast(a->e[0], a->e[1], t1);            // t1 = a0+a1
	mp_addfast(b->e[0], b->e[1], t2);            // t2 = b0+b1
	mp_mul(a->e[0], b->e[0], tt1, NWORDS_FIELD); // tt1 = a0*b0
	mp_mul(a->e[1], b->e[1], tt2, NWORDS_FIELD); // tt2 = a1*b1
	mp_mul(t1, t2, tt3, NWORDS_FIELD);     // tt3 = (a0+a1)*(b0+b1)
	mp_dblsubfast(tt1, tt2, tt3);          // tt3 = (a0+a1)*(b0+b1) - a0*b0 - a1*b1
	mp_subaddfast(tt1, tt2, tt1);          // tt1 = a0*b0 - a1*b1 + p*2^MAXBITS_FIELD if a0*b0 - a1*b1 < 0, else tt1 = a0*b0 - a1*b1
	rdc_mont(tt3, c->e[1]);                   // c[1] = (a0+a1)*(b0+b1) - a0*b0 - a1*b1
	rdc_mont(tt1, c->e[0]);                   // c[0] = a0*b0 - a1*b1
}

void fpinv_chain_mont(felm_t a) { // Chain to compute a^(p-3)/4 using Montgomery arithmetic.
	unsigned int i, j;

	felm_t t[31], tt;

	// Precomputed table
	fpsqr_mont(a, tt);
	fpmul_mont(a, tt, t[0]);
	for (i = 0; i <= 29; i++)
		fpmul_mont(t[i], tt, t[i + 1]);

	fpcopy(a, tt);
	for (i = 0; i < 7; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[5], tt, tt);
	for (i = 0; i < 10; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[14], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[3], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[23], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[13], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[24], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[7], tt, tt);
	for (i = 0; i < 8; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[12], tt, tt);
	for (i = 0; i < 8; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[30], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[1], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[30], tt, tt);
	for (i = 0; i < 7; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[21], tt, tt);
	for (i = 0; i < 9; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[2], tt, tt);
	for (i = 0; i < 9; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[19], tt, tt);
	for (i = 0; i < 9; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[1], tt, tt);
	for (i = 0; i < 7; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[24], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[26], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[16], tt, tt);
	for (i = 0; i < 7; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[10], tt, tt);
	for (i = 0; i < 7; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[6], tt, tt);
	for (i = 0; i < 7; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[0], tt, tt);
	for (i = 0; i < 9; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[20], tt, tt);
	for (i = 0; i < 8; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[9], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[25], tt, tt);
	for (i = 0; i < 9; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[30], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[26], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(a, tt, tt);
	for (i = 0; i < 7; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[28], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[6], tt, tt);
	for (i = 0; i < 6; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[10], tt, tt);
	for (i = 0; i < 9; i++)
		fpsqr_mont(tt, tt);
	fpmul_mont(t[22], tt, tt);
	for (j = 0; j < 35; j++) {
		for (i = 0; i < 6; i++)
			fpsqr_mont(tt, tt);
		fpmul_mont(t[30], tt, tt);
	}
	fpcopy(tt, a);
}

void fp2inv_mont(f2elm_t *a) { // GF(p^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2).
	f2elm_t t1;

	fpsqr_mont(a->e[0], t1.e[0]);    // t10 = a0^2
	fpsqr_mont(a->e[1], t1.e[1]);    // t11 = a1^2
	fpadd(t1.e[0], t1.e[1], t1.e[0]); // t10 = a0^2+a1^2
	fpinv_mont(t1.e[0]);          // t10 = (a0^2+a1^2)^-1
	fpneg(a->e[1]);                // a = a0-i*a1
	fpmul_mont(a->e[0], t1.e[0], a->e[0]);
	fpmul_mont(a->e[1], t1.e[0], a->e[1]); // a = (a0-i*a1)*(a0^2+a1^2)^-1
}

void to_fp2mont(const f2elm_t *a, f2elm_t *mc) { // Conversion of a GF(p^2) element to Montgomery representation,
	                                                  // mc_i = a_i*R^2*R^(-1) = a_i*R in GF(p^2).

	to_mont(a->e[0], mc->e[0]);
	to_mont(a->e[1], mc->e[1]);
}

void from_fp2mont(const f2elm_t *ma, f2elm_t *c) { // Conversion of a GF(p^2) element from Montgomery representation to standard representation,
	                                                    // c_i = ma_i*R^(-1) = a_i in GF(p^2).

	from_mont(ma->e[0], c->e[0]);
	from_mont(ma->e[1], c->e[1]);
}

unsigned int mp_add(const digit_t *a, const digit_t *b, digit_t *c, const unsigned int nwords) { // Multiprecision addition, c = a+b, where lng(a) = lng(b) = nwords. Returns the carry bit.
	unsigned int i, carry = 0;

	for (i = 0; i < nwords; i++) {
		ADDC(carry, a[i], b[i], carry, c[i]);
	}

	return carry;
}

void mp_shiftr1(digit_t *x, const unsigned int nwords) { // Multiprecision right shift by one.
	unsigned int i;

	for (i = 0; i < nwords - 1; i++) {
		SHIFTR(x[i + 1], x[i], 1, x[i], RADIX);
	}
	x[nwords - 1] >>= 1;
}
