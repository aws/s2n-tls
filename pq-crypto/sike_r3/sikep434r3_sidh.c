/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: ephemeral supersingular isogeny Diffie-Hellman key exchange (SIDH)
*********************************************************************************************/

#include "sikep434r3.h"
#include "pq-crypto/s2n_pq_random.h"
#include "utils/s2n_safety.h"
#include "sikep434r3_fpx.h"
#include "sikep434r3_ec_isogeny.h"
#include "sikep434r3_api.h"

/* Initialization of basis points */
static void init_basis(const digit_t *gen, f2elm_t *XP, f2elm_t *XQ, f2elm_t *XR)
{
    fpcopy(gen,                  XP->e[0]);
    fpcopy(gen +   S2N_SIKE_P434_R3_NWORDS_FIELD, XP->e[1]);
    fpcopy(gen + 2*S2N_SIKE_P434_R3_NWORDS_FIELD, XQ->e[0]);
    fpcopy(gen + 3*S2N_SIKE_P434_R3_NWORDS_FIELD, XQ->e[1]);
    fpcopy(gen + 4*S2N_SIKE_P434_R3_NWORDS_FIELD, XR->e[0]);
    fpcopy(gen + 5*S2N_SIKE_P434_R3_NWORDS_FIELD, XR->e[1]);
}

/* Generation of Bob's secret key
 * Outputs random value in [0, 2^Floor(Log(2, oB)) - 1] */
int random_mod_order_B(unsigned char* random_digits)
{
    POSIX_GUARD_RESULT(s2n_get_random_bytes(random_digits, S2N_SIKE_P434_R3_SECRETKEY_B_BYTES));
    random_digits[S2N_SIKE_P434_R3_SECRETKEY_B_BYTES-1] &= S2N_SIKE_P434_R3_MASK_BOB; /* Masking last byte */

    return 0;
}

/* Alice's ephemeral public key generation
 * Input:  a private key PrivateKeyA in the range [0, 2^eA - 1].
 * Output: the public key PublicKeyA consisting of 3 elements in GF(p^2) which are encoded
 *     by removing leading 0 bytes. */
int EphemeralKeyGeneration_A(const unsigned char* PrivateKeyA, unsigned char* PublicKeyA)
{
    point_proj_t R, phiP = {0}, phiQ = {0}, phiR = {0}, pts[S2N_SIKE_P434_R3_MAX_INT_POINTS_ALICE];
    f2elm_t _XPA, _XQA, _XRA, coeff[3], _A24plus = {0}, _C24 = {0}, _A = {0};
    f2elm_t *XPA=&_XPA, *XQA=&_XQA, *XRA=&_XRA, *A24plus=&_A24plus, *C24=&_C24, *A=&_A;
    unsigned int i, row, m, tree_index = 0, pts_index[S2N_SIKE_P434_R3_MAX_INT_POINTS_ALICE], npts = 0, ii = 0;
    digit_t SecretKeyA[S2N_SIKE_P434_R3_NWORDS_ORDER] = {0};

    /* Initialize basis points */
    init_basis((const digit_t*)A_gen, XPA, XQA, XRA);
    init_basis((const digit_t*)B_gen, &phiP->X, &phiQ->X, &phiR->X);
    fpcopy((const digit_t*)&Montgomery_one, (phiP->Z.e)[0]);
    fpcopy((const digit_t*)&Montgomery_one, (phiQ->Z.e)[0]);
    fpcopy((const digit_t*)&Montgomery_one, (phiR->Z.e)[0]);

    /* Initialize constants: A24plus = A+2C, C24 = 4C, where A=6, C=1 */
    fpcopy((const digit_t*)&Montgomery_one, A24plus->e[0]);
    mp2_add(A24plus, A24plus, A24plus);
    mp2_add(A24plus, A24plus, C24);
    mp2_add(A24plus, C24, A);
    mp2_add(C24, C24, A24plus);

    /* Retrieve kernel point */
    decode_to_digits(PrivateKeyA, SecretKeyA, S2N_SIKE_P434_R3_SECRETKEY_A_BYTES, S2N_SIKE_P434_R3_NWORDS_ORDER);
    LADDER3PT(XPA, XQA, XRA, SecretKeyA, S2N_SIKE_P434_R3_ALICE, R, A);

    /* Traverse tree */
    tree_index = 0;
    for (row = 1; row < S2N_SIKE_P434_R3_MAX_ALICE; row++) {
        while (tree_index < S2N_SIKE_P434_R3_MAX_ALICE-row) {
            fp2copy(&R->X, &pts[npts]->X);
            fp2copy(&R->Z, &pts[npts]->Z);
            pts_index[npts++] = tree_index;
            m = strat_Alice[ii++];
            xDBLe(R, R, A24plus, C24, (int)(2*m));
            tree_index += m;
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
        tree_index = pts_index[npts-1];
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
                
    /* Format public key */
    fp2_encode(&phiP->X, PublicKeyA);
    fp2_encode(&phiQ->X, PublicKeyA + S2N_SIKE_P434_R3_FP2_ENCODED_BYTES);
    fp2_encode(&phiR->X, PublicKeyA + 2*S2N_SIKE_P434_R3_FP2_ENCODED_BYTES);

    return 0;
}

/* Bob's ephemeral public key generation
 * Input:  a private key PrivateKeyB in the range [0, 2^Floor(Log(2,oB)) - 1].
 * Output: the public key PublicKeyB consisting of 3 elements in GF(p^2) which are encoded
 *     by removing leading 0 bytes. */
int EphemeralKeyGeneration_B(const unsigned char* PrivateKeyB, unsigned char* PublicKeyB)
{
    point_proj_t R, phiP = {0}, phiQ = {0}, phiR = {0}, pts[S2N_SIKE_P434_R3_MAX_INT_POINTS_BOB];
    f2elm_t _XPB, _XQB, _XRB, coeff[3], _A24plus = {0}, _A24minus = {0}, _A = {0};
    f2elm_t *XPB=&_XPB, *XQB=&_XQB, *XRB=&_XRB, *A24plus=&_A24plus, *A24minus=&_A24minus, *A=&_A;

    unsigned int i, row, m, tree_index = 0, pts_index[S2N_SIKE_P434_R3_MAX_INT_POINTS_BOB], npts = 0, ii = 0;
    digit_t SecretKeyB[S2N_SIKE_P434_R3_NWORDS_ORDER] = {0};

    /* Initialize basis points */
    init_basis((const digit_t*)B_gen, XPB, XQB, XRB);
    init_basis((const digit_t*)A_gen, &phiP->X, &phiQ->X, &phiR->X);
    fpcopy((const digit_t*)&Montgomery_one, (phiP->Z.e)[0]);
    fpcopy((const digit_t*)&Montgomery_one, (phiQ->Z.e)[0]);
    fpcopy((const digit_t*)&Montgomery_one, (phiR->Z.e)[0]);

    /* Initialize constants: A24minus = A-2C, A24plus = A+2C, where A=6, C=1 */
    fpcopy((const digit_t*)&Montgomery_one, A24plus->e[0]);
    mp2_add(A24plus, A24plus, A24plus);
    mp2_add(A24plus, A24plus, A24minus);
    mp2_add(A24plus, A24minus, A);
    mp2_add(A24minus, A24minus, A24plus);

    /* Retrieve kernel point */
    decode_to_digits(PrivateKeyB, SecretKeyB, S2N_SIKE_P434_R3_SECRETKEY_B_BYTES, S2N_SIKE_P434_R3_NWORDS_ORDER);
    LADDER3PT(XPB, XQB, XRB, SecretKeyB, S2N_SIKE_P434_R3_BOB, R, A);
    
    /* Traverse tree */
    tree_index = 0;
    for (row = 1; row < S2N_SIKE_P434_R3_MAX_BOB; row++) {
        while (tree_index < S2N_SIKE_P434_R3_MAX_BOB-row) {
            fp2copy(&R->X, &pts[npts]->X);
            fp2copy(&R->Z, &pts[npts]->Z);
            pts_index[npts++] = tree_index;
            m = strat_Bob[ii++];
            xTPLe(R, R, A24minus, A24plus, (int)m);
            tree_index += m;
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
        tree_index = pts_index[npts-1];
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

    /* Format public key */
    fp2_encode(&phiP->X, PublicKeyB);
    fp2_encode(&phiQ->X, PublicKeyB + S2N_SIKE_P434_R3_FP2_ENCODED_BYTES);
    fp2_encode(&phiR->X, PublicKeyB + 2*S2N_SIKE_P434_R3_FP2_ENCODED_BYTES);

    return 0;
}

/* Alice's ephemeral shared secret computation
 * It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's public key PublicKeyB
 * Inputs: Alice's PrivateKeyA is an integer in the range [0, oA-1].
 *     Bob's PublicKeyB consists of 3 elements in GF(p^2) encoded by removing leading 0 bytes.
 * Output: a shared secret SharedSecretA that consists of one element in GF(p^2) encoded
 *     by removing leading 0 bytes.   */
int EphemeralSecretAgreement_A(const unsigned char* PrivateKeyA, const unsigned char* PublicKeyB,
        unsigned char* SharedSecretA)
{
    point_proj_t R, pts[S2N_SIKE_P434_R3_MAX_INT_POINTS_ALICE];
    f2elm_t coeff[3], PKB[3], _jinv;
    f2elm_t _A24plus = {0}, _C24 = {0}, _A = {0};
    f2elm_t *jinv=&_jinv, *A24plus=&_A24plus, *C24=&_C24, *A=&_A;
    unsigned int i, row, m, tree_index = 0, pts_index[S2N_SIKE_P434_R3_MAX_INT_POINTS_ALICE], npts = 0, ii = 0;
    digit_t SecretKeyA[S2N_SIKE_P434_R3_NWORDS_ORDER] = {0};
      
    /* Initialize images of Bob's basis */
    fp2_decode(PublicKeyB, &PKB[0]);
    fp2_decode(PublicKeyB + S2N_SIKE_P434_R3_FP2_ENCODED_BYTES, &PKB[1]);
    fp2_decode(PublicKeyB + 2*S2N_SIKE_P434_R3_FP2_ENCODED_BYTES, &PKB[2]);

    /* Initialize constants: A24plus = A+2C, C24 = 4C, where C=1 */
    get_A(&PKB[0], &PKB[1], &PKB[2], A);
    mp_add((const digit_t*)&Montgomery_one, (const digit_t*)&Montgomery_one, C24->e[0], S2N_SIKE_P434_R3_NWORDS_FIELD);
    mp2_add(A, C24, A24plus);
    mp_add(C24->e[0], C24->e[0], C24->e[0], S2N_SIKE_P434_R3_NWORDS_FIELD);

    /* Retrieve kernel point */
    decode_to_digits(PrivateKeyA, SecretKeyA, S2N_SIKE_P434_R3_SECRETKEY_A_BYTES, S2N_SIKE_P434_R3_NWORDS_ORDER);
    LADDER3PT(&PKB[0], &PKB[1], &PKB[2], SecretKeyA, S2N_SIKE_P434_R3_ALICE, R, A);

    /* Traverse tree */
    tree_index = 0;
    for (row = 1; row < S2N_SIKE_P434_R3_MAX_ALICE; row++) {
        while (tree_index < S2N_SIKE_P434_R3_MAX_ALICE-row) {
            fp2copy(&R->X, &pts[npts]->X);
            fp2copy(&R->Z, &pts[npts]->Z);
            pts_index[npts++] = tree_index;
            m = strat_Alice[ii++];
            xDBLe(R, R, A24plus, C24, (int)(2*m));
            tree_index += m;
        }
        get_4_isog(R, A24plus, C24, coeff);

        for (i = 0; i < npts; i++) {
            eval_4_isog(pts[i], coeff);
        }

        fp2copy(&pts[npts-1]->X, &R->X);
        fp2copy(&pts[npts-1]->Z, &R->Z);
        tree_index = pts_index[npts-1];
        npts -= 1;
    }

    get_4_isog(R, A24plus, C24, coeff);
    mp2_add(A24plus, A24plus, A24plus);
    fp2sub(A24plus, C24, A24plus);
    fp2add(A24plus, A24plus, A24plus);
    j_inv(A24plus, C24, jinv);
    fp2_encode(jinv, SharedSecretA); /* Format shared secret */

    return 0;
}

/* Bob's ephemeral shared secret computation
 * It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's public key PublicKeyA
 * Inputs: Bob's PrivateKeyB is an integer in the range [0, 2^Floor(Log(2,oB)) - 1].
 *     Alice's PublicKeyA consists of 3 elements in GF(p^2) encoded by removing leading 0 bytes.
 * Output: a shared secret SharedSecretB that consists of one element in GF(p^2) encoded
 *     by removing leading 0 bytes.   */
int EphemeralSecretAgreement_B(const unsigned char* PrivateKeyB, const unsigned char* PublicKeyA,
        unsigned char* SharedSecretB)
{
    point_proj_t R, pts[S2N_SIKE_P434_R3_MAX_INT_POINTS_BOB];
    f2elm_t coeff[3], PKB[3], _jinv;
    f2elm_t _A24plus = {0}, _A24minus = {0}, _A = {0};
    f2elm_t *jinv=&_jinv, *A24plus=&_A24plus, *A24minus=&_A24minus, *A=&_A;
    unsigned int i, row, m, tree_index = 0, pts_index[S2N_SIKE_P434_R3_MAX_INT_POINTS_BOB], npts = 0, ii = 0;
    digit_t SecretKeyB[S2N_SIKE_P434_R3_NWORDS_ORDER] = {0};
      
    /* Initialize images of Alice's basis */
    fp2_decode(PublicKeyA, &PKB[0]);
    fp2_decode(PublicKeyA + S2N_SIKE_P434_R3_FP2_ENCODED_BYTES, &PKB[1]);
    fp2_decode(PublicKeyA + 2*S2N_SIKE_P434_R3_FP2_ENCODED_BYTES, &PKB[2]);

    /* Initialize constants: A24plus = A+2C, A24minus = A-2C, where C=1 */
    get_A(&PKB[0], &PKB[1], &PKB[2], A);
    mp_add((const digit_t*)&Montgomery_one, (const digit_t*)&Montgomery_one, A24minus->e[0], S2N_SIKE_P434_R3_NWORDS_FIELD);
    mp2_add(A, A24minus, A24plus);
    mp2_sub_p2(A, A24minus, A24minus);

    /* Retrieve kernel point */
    decode_to_digits(PrivateKeyB, SecretKeyB, S2N_SIKE_P434_R3_SECRETKEY_B_BYTES, S2N_SIKE_P434_R3_NWORDS_ORDER);
    LADDER3PT(&PKB[0], &PKB[1], &PKB[2], SecretKeyB, S2N_SIKE_P434_R3_BOB, R, A);
    
    /* Traverse tree */
    tree_index = 0;
    for (row = 1; row < S2N_SIKE_P434_R3_MAX_BOB; row++) {
        while (tree_index < S2N_SIKE_P434_R3_MAX_BOB-row) {
            fp2copy(&R->X, &pts[npts]->X);
            fp2copy(&R->Z, &pts[npts]->Z);
            pts_index[npts++] = tree_index;
            m = strat_Bob[ii++];
            xTPLe(R, R, A24minus, A24plus, (int)m);
            tree_index += m;
        }
        get_3_isog(R, A24minus, A24plus, coeff);

        for (i = 0; i < npts; i++) {
            eval_3_isog(pts[i], coeff);
        } 

        fp2copy(&pts[npts-1]->X, &R->X);
        fp2copy(&pts[npts-1]->Z, &R->Z);
        tree_index = pts_index[npts-1];
        npts -= 1;
    }
     
    get_3_isog(R, A24minus, A24plus, coeff);
    fp2add(A24plus, A24minus, A);
    fp2add(A, A, A);
    fp2sub(A24plus, A24minus, A24plus);
    j_inv(A, A24plus, jinv);
    fp2_encode(jinv, SharedSecretB); /* Format shared secret */

    return 0;
}
