/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: ephemeral supersingular isogeny Diffie-Hellman key exchange (SIDH)
*********************************************************************************************/

#include "sike_r1_namespace.h"
#include "P503_internal_r1.h"
#include "pq-crypto/s2n_pq_random.h"
#include "utils/s2n_safety.h"

static void clear_words(void* mem, digit_t nwords)
{ // Clear digits from memory. "nwords" indicates the number of digits to be zeroed.
  // This function uses the volatile type qualifier to inform the compiler not to optimize out the memory clearing.
    unsigned int i;
    volatile digit_t *v = mem;

    for (i = 0; i < nwords; i++) {
        v[i] = 0;
    }
}

static void init_basis(const digit_t *gen, f2elm_t *XP, f2elm_t *XQ, f2elm_t *XR)
{ // Initialization of basis points

    fpcopy(gen,                  XP->e[0]);
    fpcopy(gen +   NWORDS_FIELD, XP->e[1]);
    fpcopy(gen + 2*NWORDS_FIELD, XQ->e[0]);
    fpzero(XQ->e[1]);
    fpcopy(gen + 3*NWORDS_FIELD, XR->e[0]);
    fpcopy(gen + 4*NWORDS_FIELD, XR->e[1]);
}


static void fp2_encode(const f2elm_t *x, unsigned char *enc)
{ // Conversion of GF(p^2) element from Montgomery to standard representation, and encoding by removing leading 0 bytes
    unsigned int i;
    f2elm_t t;

    from_fp2mont(x, &t);
    for (i = 0; i < FP2_ENCODED_BYTES / 2; i++) {
        enc[i] = ((unsigned char*)t.e)[i];
        enc[i + FP2_ENCODED_BYTES / 2] = ((unsigned char*)t.e)[i + MAXBITS_FIELD / 8];
    }
}


static void fp2_decode(const unsigned char *enc, f2elm_t *x)
{ // Parse byte sequence back into GF(p^2) element, and conversion to Montgomery representation
    unsigned int i;

    for (i = 0; i < 2*(MAXBITS_FIELD / 8); i++) ((unsigned char *)x->e)[i] = 0;
    for (i = 0; i < FP2_ENCODED_BYTES / 2; i++) {
        ((unsigned char*)x->e)[i] = enc[i];
        ((unsigned char*)x->e)[i + MAXBITS_FIELD / 8] = enc[i + FP2_ENCODED_BYTES / 2];
    }
    to_fp2mont(x, x);
}

int random_mod_order_B(unsigned char* random_digits)
{  // Generation of Bob's secret key
   // Outputs random value in [0, 2^Floor(Log(2, oB)) - 1]
    unsigned long long nbytes = NBITS_TO_NBYTES(OBOB_BITS-1);

    clear_words((void*)random_digits, MAXWORDS_ORDER);
    POSIX_GUARD_RESULT(s2n_get_random_bytes(random_digits, nbytes));
    random_digits[nbytes-1] &= MASK_BOB;     // Masking last byte

    return S2N_SUCCESS;
}


int EphemeralKeyGeneration_A(const digit_t* PrivateKeyA, unsigned char* PublicKeyA)
{ // Alice's ephemeral public key generation
  // Input:  a private key PrivateKeyA in the range [0, 2^eA - 1].
  // Output: the public key PublicKeyA consisting of 3 elements in GF(p^2) which are encoded by removing leading 0 bytes.
    point_proj_t R, phiP = {0}, phiQ = {0}, phiR = {0}, pts[MAX_INT_POINTS_ALICE];
    f2elm_t _XPA, _XQA, _XRA, coeff[3], _A24plus = {0}, _C24 = {0}, _A = {0};
    f2elm_t *XPA=&_XPA, *XQA=&_XQA, *XRA=&_XRA, *A24plus=&_A24plus, *C24=&_C24, *A=&_A;
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_ALICE], npts = 0, ii = 0;


    // Initialize basis points
    init_basis((const digit_t*)A_gen, XPA, XQA, XRA);
    init_basis((const digit_t*)B_gen, &phiP->X, &phiQ->X, &phiR->X);
    fpcopy((const digit_t*)&Montgomery_one, (phiP->Z.e)[0]);
    fpcopy((const digit_t*)&Montgomery_one, (phiQ->Z.e)[0]);
    fpcopy((const digit_t*)&Montgomery_one, (phiR->Z.e)[0]);

    // Initialize constants
    fpcopy((const digit_t*)&Montgomery_one, A24plus->e[0]);
    fp2add(A24plus, A24plus, C24);

    // Retrieve kernel point
    LADDER3PT(XPA, XQA, XRA, PrivateKeyA, ALICE, R, A);

    // Traverse tree
    index = 0;
    for (row = 1; row < MAX_Alice; row++) {
        while (index < MAX_Alice-row) {
            fp2copy(&R->X, &pts[npts]->X);
            fp2copy(&R->Z, &pts[npts]->Z);
            pts_index[npts++] = index;
            m = strat_Alice[ii++];
            xDBLe(R, R, A24plus, C24, (int)(2*m));
            index += m;
        }
        get_4_isog(R, A24plus, C24, coeff);

        for (i = 0; i < npts; i++) {
            eval_4_isog(pts[i], coeff);
        }
        eval_4_isog(phiP, coeff);
        eval_4_isog(phiQ, coeff);
        eval_4_isog(phiR, coeff);

        fp2copy(&pts[npts-1]->X, &R->X);
        fp2copy(&pts[npts-1]->Z, &R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_4_isog(R, A24plus, C24, coeff);
    eval_4_isog(phiP, coeff);
    eval_4_isog(phiQ, coeff);
    eval_4_isog(phiR, coeff);

    inv_3_way(&phiP->Z, &phiQ->Z, &phiR->Z);
    fp2mul_mont(&phiP->X, &phiP->Z, &phiP->X);
    fp2mul_mont(&phiQ->X, &phiQ->Z, &phiQ->X);
    fp2mul_mont(&phiR->X, &phiR->Z, &phiR->X);

    // Format public key
    fp2_encode(&phiP->X, PublicKeyA);
    fp2_encode(&phiQ->X, PublicKeyA + FP2_ENCODED_BYTES);
    fp2_encode(&phiR->X, PublicKeyA + 2*FP2_ENCODED_BYTES);

    return S2N_SUCCESS;
}


int EphemeralKeyGeneration_B(const digit_t* PrivateKeyB, unsigned char* PublicKeyB)
{ // Bob's ephemeral public key generation
  // Input:  a private key PrivateKeyB in the range [0, 2^Floor(Log(2,oB)) - 1].
  // Output: the public key PublicKeyB consisting of 3 elements in GF(p^2) which are encoded by removing leading 0 bytes.
    point_proj_t R, phiP = {0}, phiQ = {0}, phiR = {0}, pts[MAX_INT_POINTS_BOB];
    f2elm_t _XPB, _XQB, _XRB, coeff[3], _A24plus = {0}, _A24minus = {0}, _A = {0};
    f2elm_t *XPB=&_XPB, *XQB=&_XQB, *XRB=&_XRB, *A24plus=&_A24plus, *A24minus=&_A24minus, *A=&_A;
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0, ii = 0;

    // Initialize basis points
    init_basis((const digit_t*)B_gen, XPB, XQB, XRB);
    init_basis((const digit_t*)A_gen, &phiP->X, &phiQ->X, &phiR->X);
    fpcopy((const digit_t*)&Montgomery_one, (phiP->Z.e)[0]);
    fpcopy((const digit_t*)&Montgomery_one, (phiQ->Z.e)[0]);
    fpcopy((const digit_t*)&Montgomery_one, (phiR->Z.e)[0]);

    // Initialize constants
    fpcopy((const digit_t*)&Montgomery_one, A24plus->e[0]);
    fp2add(A24plus, A24plus, A24plus);
    fp2copy(A24plus, A24minus);
    fp2neg(A24minus);

    // Retrieve kernel point
    LADDER3PT(XPB, XQB, XRB, PrivateKeyB, BOB, R, A);

    // Traverse tree
    index = 0;
    for (row = 1; row < MAX_Bob; row++) {
        while (index < MAX_Bob-row) {
            fp2copy(&R->X, &pts[npts]->X);
            fp2copy(&R->Z, &pts[npts]->Z);
            pts_index[npts++] = index;
            m = strat_Bob[ii++];
            xTPLe(R, R, A24minus, A24plus, (int)m);
            index += m;
        }
        get_3_isog(R, A24minus, A24plus, coeff);

        for (i = 0; i < npts; i++) {
            eval_3_isog(pts[i], coeff);
        }
        eval_3_isog(phiP, coeff);
        eval_3_isog(phiQ, coeff);
        eval_3_isog(phiR, coeff);

        fp2copy(&pts[npts-1]->X, &R->X);
        fp2copy(&pts[npts-1]->Z, &R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_3_isog(R, A24minus, A24plus, coeff);
    eval_3_isog(phiP, coeff);
    eval_3_isog(phiQ, coeff);
    eval_3_isog(phiR, coeff);

    inv_3_way(&phiP->Z, &phiQ->Z, &phiR->Z);
    fp2mul_mont(&phiP->X, &phiP->Z, &phiP->X);
    fp2mul_mont(&phiQ->X, &phiQ->Z, &phiQ->X);
    fp2mul_mont(&phiR->X, &phiR->Z, &phiR->X);

    // Format public key
    fp2_encode(&phiP->X, PublicKeyB);
    fp2_encode(&phiQ->X, PublicKeyB + FP2_ENCODED_BYTES);
    fp2_encode(&phiR->X, PublicKeyB + 2*FP2_ENCODED_BYTES);

    return S2N_SUCCESS;
}


int EphemeralSecretAgreement_A(const digit_t* PrivateKeyA, const unsigned char* PublicKeyB, unsigned char* SharedSecretA)
{ // Alice's ephemeral shared secret computation
  // It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's public key PublicKeyB
  // Inputs: Alice's PrivateKeyA is an integer in the range [0, oA-1].
  //         Bob's PublicKeyB consists of 3 elements in GF(p^2) encoded by removing leading 0 bytes.
  // Output: a shared secret SharedSecretA that consists of one element in GF(p^2) encoded by removing leading 0 bytes.
    point_proj_t R, pts[MAX_INT_POINTS_ALICE];
    f2elm_t coeff[3], PKB[3], _jinv;
    f2elm_t _A24plus = {0}, _C24 = {0}, _A = {0};
    f2elm_t *jinv=&_jinv, *A24plus=&_A24plus, *C24=&_C24, *A=&_A;
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_ALICE], npts = 0, ii = 0;

    // Initialize images of Bob's basis
    fp2_decode(PublicKeyB, &PKB[0]);
    fp2_decode(PublicKeyB + FP2_ENCODED_BYTES, &PKB[1]);
    fp2_decode(PublicKeyB + 2*FP2_ENCODED_BYTES, &PKB[2]);

    // Initialize constants
    get_A(&PKB[0], &PKB[1], &PKB[2], A); // TODO: Can return projective A?
    fpadd((const digit_t*)&Montgomery_one, (const digit_t*)&Montgomery_one, C24->e[0]);
    fp2add(A, C24, A24plus);
    fpadd(C24->e[0], C24->e[0], C24->e[0]);

    // Retrieve kernel point
    LADDER3PT(&PKB[0], &PKB[1], &PKB[2], PrivateKeyA, ALICE, R, A);

    // Traverse tree
    index = 0;
    for (row = 1; row < MAX_Alice; row++) {
        while (index < MAX_Alice-row) {
            fp2copy(&R->X, &pts[npts]->X);
            fp2copy(&R->Z, &pts[npts]->Z);
            pts_index[npts++] = index;
            m = strat_Alice[ii++];
            xDBLe(R, R, A24plus, C24, (int)(2*m));
            index += m;
        }
        get_4_isog(R, A24plus, C24, coeff);

        for (i = 0; i < npts; i++) {
            eval_4_isog(pts[i], coeff);
        }

        fp2copy(&pts[npts-1]->X, &R->X);
        fp2copy(&pts[npts-1]->Z, &R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_4_isog(R, A24plus, C24, coeff);
    fp2div2(C24, C24);
    fp2sub(A24plus, C24, A24plus);
    fp2div2(C24, C24);
    j_inv(A24plus, C24, jinv);
    fp2_encode(jinv, SharedSecretA);    // Format shared secret

    return S2N_SUCCESS;
}


int EphemeralSecretAgreement_B(const digit_t* PrivateKeyB, const unsigned char* PublicKeyA, unsigned char* SharedSecretB)
{ // Bob's ephemeral shared secret computation
  // It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's public key PublicKeyA
  // Inputs: Bob's PrivateKeyB is an integer in the range [0, 2^Floor(Log(2,oB)) - 1].
  //         Alice's PublicKeyA consists of 3 elements in GF(p^2) encoded by removing leading 0 bytes.
  // Output: a shared secret SharedSecretB that consists of one element in GF(p^2) encoded by removing leading 0 bytes.
    point_proj_t R, pts[MAX_INT_POINTS_BOB];
    f2elm_t coeff[3], PKB[3], _jinv;
    f2elm_t _A24plus = {0}, _A24minus = {0}, _A = {0};
    f2elm_t *jinv=&_jinv, *A24plus=&_A24plus, *A24minus=&_A24minus, *A=&_A;
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0, ii = 0;

    // Initialize images of Alice's basis
    fp2_decode(PublicKeyA, &PKB[0]);
    fp2_decode(PublicKeyA + FP2_ENCODED_BYTES, &PKB[1]);
    fp2_decode(PublicKeyA + 2*FP2_ENCODED_BYTES, &PKB[2]);

    // Initialize constants
    get_A(&PKB[0], &PKB[1], &PKB[2], A); // TODO: Can return projective A?
    fpadd((const digit_t*)&Montgomery_one, (const digit_t*)&Montgomery_one, A24minus->e[0]);
    fp2add(A, A24minus, A24plus);
    fp2sub(A, A24minus, A24minus);

    // Retrieve kernel point
    LADDER3PT(&PKB[0], &PKB[1], &PKB[2], PrivateKeyB, BOB, R, A);

    // Traverse tree
    index = 0;
    for (row = 1; row < MAX_Bob; row++) {
        while (index < MAX_Bob-row) {
            fp2copy(&R->X, &pts[npts]->X);
            fp2copy(&R->Z, &pts[npts]->Z);
            pts_index[npts++] = index;
            m = strat_Bob[ii++];
            xTPLe(R, R, A24minus, A24plus, (int)m);
            index += m;
        }
        get_3_isog(R, A24minus, A24plus, coeff);

        for (i = 0; i < npts; i++) {
            eval_3_isog(pts[i], coeff);
        }

        fp2copy(&pts[npts-1]->X, &R->X);
        fp2copy(&pts[npts-1]->Z, &R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_3_isog(R, A24minus, A24plus, coeff);
    fp2add(A24plus, A24minus, A);
    fp2add(A, A, A);
    fp2sub(A24plus, A24minus, A24plus);
    j_inv(A, A24plus, jinv);
    fp2_encode(jinv, SharedSecretB);    // Format shared secret

    return S2N_SUCCESS;
}
