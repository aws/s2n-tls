/******************************************************************************
 * BIKE -- Bit Flipping Key Encapsulation
 *
 * Copyright (c) 2017 Nir Drucker, Shay Gueron, Rafael Misoczki, Tobias Oder, Tim Gueneysu
 * (drucker.nir@gmail.com, shay.gueron@gmail.com, rafael.misoczki@intel.com, tobias.oder@rub.de, tim.gueneysu@rub.de)
 *
 * Permission to use this code for BIKE is granted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * * The names of the contributors may not be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS CORPORATION OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "stdio.h"
#include "string.h"

#include "bike1_l1_kem.h"
#include "parallel_hash.h"
#include "openssl_utils.h"
#include "decode.h"
#include "sampling.h"
#include "aes_ctr_prf.h"
#include "conversions.h"

_INLINE_ status_t encrypt(OUT ct_t* ct,
        IN const uint8_t* e,
        IN const uint8_t* ep __attribute__ ((__unused__)) ,
        IN const pk_t* pk,
        IN const seed_t* seed)
{
    status_t res = SUCCESS;

#ifndef BIKE2
    uint8_t c0[R_SIZE] = {0};
#endif
    uint8_t c1[R_SIZE] = {0};

    uint8_t e0[R_SIZE] = {0};
    uint8_t e1[R_SIZE] = {0};

    ossl_split_polynomial(e0, e1, e);

#ifdef BIKE1
    // ct = (m*pk0 + e0, m*pk1 + e1)
    uint8_t m[R_SIZE] = {0};
    sample_uniform_r_bits(m, seed, NO_RESTRICTION);
    cyclic_product(c0, m, pk->u.v.val0);
    cyclic_product(c1, m, pk->u.v.val1);
    ossl_add(ct->u.v.val0, c0, e0);
    ossl_add(ct->u.v.val1, c1, e1);
#else
#ifdef BIKE2
	UNUSED(seed);
    // ct = (e1*pk1 + e0)
    cyclic_product(c1, e1, pk->u.v.val1);
    ossl_add(ct->u.v.val0, c1, e0);
    for (uint32_t i = 0; i < R_SIZE; i++)
        ct->u.v.val1[i] = 0;
#else
#ifdef BIKE3
    UNUSED(seed);
    // ct = (e1*pk0 + e_extra, e1*pk1 + e0)
    cyclic_product(c0, e1, pk->u.v.val0);
    cyclic_product(c1, e1, pk->u.v.val1);
    ossl_add(ct->u.v.val0, c0, ep);
    ossl_add(ct->u.v.val1, c1, e0);
#endif
#endif
#endif

    EDMSG("c0: "); print((uint64_t*)ct->u.v.val0, R_BITS);
    EDMSG("c1: "); print((uint64_t*)ct->u.v.val1, R_BITS);

    return res;
}


//Generate the Shared Secret (K(e))
_INLINE_ status_t get_ss(OUT ss_t* out, IN uint8_t* e)
{
    status_t res = SUCCESS;

    DMSG("    Enter get_ss.\n");

    sha384_hash_t hash = {0};

    //Calculate the hash.
    parallel_hash(&hash, e, N_SIZE);

    //Truncate the final hash into K.
    //By copying only the LSBs
    for(uint32_t i = 0; i < sizeof(ss_t); i++)
    {
        out->raw[i] = hash.u.raw[i];
    }

    DMSG("    Exit get_ss.\n");
    return res;
}

// transpose a row into a column:
_INLINE_ void transpose(uint8_t col[R_BITS], uint8_t row[R_BITS])
{
    col[0] = row[0];
    for (uint64_t i = 1; i < R_BITS ; ++i)
    {
        col[i] = row[(R_BITS) - i];
    }
}

_INLINE_ status_t compute_syndrome(OUT syndrome_t* syndrome,
        IN const ct_t* ct,
        IN const sk_t* sk)
{
    status_t res = SUCCESS;
    uint8_t s_tmp_bytes[R_BITS] = {0};
    uint8_t s0[R_SIZE] = {0};

#ifdef BIKE1
    // BIKE-1 syndrome: s = h0*c0 + h1*c1:
    cyclic_product(s0, sk->u.v.val0, ct->u.v.val0);
    uint8_t s1[R_SIZE] = {0};
    cyclic_product(s1, sk->u.v.val1, ct->u.v.val1);
    ossl_add(s0, s0, s1);
#else
#ifdef BIKE2
    // BIKE-2 syndrome: s = c0*h0
    cyclic_product(s0, sk->u.v.val0, ct->u.v.val0);
#else
#ifdef BIKE3
    // BIKE3 syndrome: s = c0 + c1*h0
    cyclic_product(s0, ct->u.v.val1, sk->u.v.val0);
    ossl_add(s0, s0, ct->u.v.val0);
#endif
#endif
#endif

    //Store the syndrome in a bit array
    convertByteToBinary(s_tmp_bytes, s0, R_BITS);
    transpose(syndrome->raw, s_tmp_bytes);

    return res;
}

////////////////////////////////////////////////////////////////
//The three APIs below (keypair, enc, dec) are defined by NIST:
//In addition there are two KAT versions of this API as defined.
////////////////////////////////////////////////////////////////
int BIKE1_L1_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk)
{
    //Convert to this implementation types
    sk_t* l_sk = (sk_t*)sk;
    pk_t* l_pk = (pk_t*)pk;
    status_t res = SUCCESS;

    //For NIST DRBG_CTR.
    double_seed_t seeds = {0};
    aes_ctr_prf_state_t h_prf_state = {0};

    //Get the entropy seeds.
    get_seeds(&seeds, KEYGEN_SEEDS);

    // sk = (h0, h1)
    uint8_t * h0 = l_sk->u.v.val0;
    uint8_t * h1 = l_sk->u.v.val1;

    DMSG("  Enter BIKE1_L1_crypto_kem_keypair.\n");
    DMSG("    Calculating the secret key.\n");

#ifdef BIKE1
    uint8_t g[R_SIZE] = {0};
#endif
#ifdef BIKE2
    uint8_t inv_h0[R_SIZE];
#endif
#ifdef BIKE3
    uint8_t tmp1[R_SIZE] = {0};
	uint8_t * g = l_pk->u.v.val1;
#endif

    //Both h0 and h1 use the same context
    init_aes_ctr_prf_state(&h_prf_state, MAX_AES_INVOKATION, &seeds.u.v.s1);

    res = generate_sparse_rep(h0, DV, R_BITS, &h_prf_state); CHECK_STATUS(res);
    res = generate_sparse_rep(h1, DV, R_BITS, &h_prf_state); CHECK_STATUS(res);

    DMSG("    Calculating the public key.\n");

#ifdef BIKE1
    //  pk = (g*h1, g*h0)
    res = sample_uniform_r_bits(g, &seeds.u.v.s2, MUST_BE_ODD);  CHECK_STATUS(res);

    cyclic_product(l_pk->u.v.val0, g, h1); CHECK_STATUS(res);
    cyclic_product(l_pk->u.v.val1, g, h0); CHECK_STATUS(res);
#else
#ifdef BIKE2
    // pk = (1, h1*h0^(-1))
	memset(l_pk->u.v.val0, 0, R_SIZE);
    l_pk->u.v.val0[0] = 1; //assume all elements initialized with 0
    ossl_mod_inv(inv_h0, h0);
    cyclic_product(l_pk->u.v.val1, h1, inv_h0);
#else
#ifdef BIKE3
    // pk = (h1 + g*h0, g)
    res = sample_uniform_r_bits(g, &seeds.u.v.s2, MUST_BE_ODD);  CHECK_STATUS(res);
    cyclic_product(tmp1, g, h0);
    ossl_add(l_pk->u.v.val0, tmp1, h1);
#endif
#endif
#endif

    EDMSG("h0: "); print((uint64_t*)l_sk->u.v.val0, R_BITS);
    EDMSG("h1: "); print((uint64_t*)l_sk->u.v.val1, R_BITS);
    EDMSG("g0: "); print((uint64_t*)l_pk->u.v.val0, R_BITS);
    EDMSG("g1: "); print((uint64_t*)l_pk->u.v.val1, R_BITS);

EXIT:
    DMSG("  Exit BIKE1_L1_crypto_kem_keypair.\n");
    return res;
}

//Encapsulate - pk is the public key,
//              ct is a key encapsulation message (ciphertext),
//              ss is the shared secret.
int BIKE1_L1_crypto_kem_enc(OUT unsigned char *ct,
        OUT unsigned char *ss,
        IN  const unsigned char *pk)
{
    DMSG("  Enter BIKE1_L1_crypto_kem_enc.\n");

    status_t res = SUCCESS;

    //Convert to these implementation types
    const pk_t* l_pk = (pk_t*)pk;
    ct_t* l_ct = (ct_t*)ct;
    ss_t* l_ss = (ss_t*)ss;

    //For NIST DRBG_CTR.
    double_seed_t seeds = {0};
    aes_ctr_prf_state_t e_prf_state = {0};

    //Get the entropy seeds.
    get_seeds(&seeds, ENCAPS_SEEDS);

    // error vector:
    uint8_t e[N_SIZE] = {0};
#ifdef BIKE3
    uint8_t e_extra[R_SIZE]={0};
#endif

    //random data generator;
    // Using first seed
    init_aes_ctr_prf_state(&e_prf_state, MAX_AES_INVOKATION, &seeds.u.v.s1);

    DMSG("    Generating error.\n");
    res = generate_sparse_rep(e, T1, N_BITS, &e_prf_state); CHECK_STATUS(res);

#ifdef BIKE3
    res = generate_sparse_rep(e_extra, T1/2, R_BITS, &e_prf_state);
#endif

    // computing ct = enc(pk, e)
    // Using second seed
    DMSG("    Encrypting.\n");
#ifdef BIKE3
    res = encrypt(l_ct, e, e_extra, l_pk, &seeds.u.v.s2);             	CHECK_STATUS(res);
#else
    res = encrypt(l_ct, e, 0, l_pk, &seeds.u.v.s2);             	CHECK_STATUS(res);
#endif

    DMSG("    Generating shared secret.\n");
    res = get_ss(l_ss, e);                                  CHECK_STATUS(res);

    EDMSG("ss: "); print((uint64_t*)l_ss->raw, sizeof(*l_ss)*8);

EXIT:

    DMSG("  Exit BIKE1_L1_crypto_kem_enc.\n");
    return res;
}

//Decapsulate - ct is a key encapsulation message (ciphertext),
//              sk is the private key,
//              ss is the shared secret
int BIKE1_L1_crypto_kem_dec(OUT unsigned char *ss,
        IN const unsigned char *ct,
        IN const unsigned char *sk)
{
    DMSG("  Enter BIKE1_L1_crypto_kem_dec.\n");
    status_t res = SUCCESS;

    //Convert to this implementation types
    const sk_t* l_sk = (sk_t*)sk;
    const ct_t* l_ct = (ct_t*)ct;
    ss_t* l_ss = (ss_t*)ss;

    DMSG("  Converting to compact rep.\n");
    uint32_t h0_compact[DV] = {0};
    uint32_t h1_compact[DV] = {0};
    convert2compact(h0_compact, l_sk->u.v.val0);
    convert2compact(h1_compact, l_sk->u.v.val1);

    DMSG("  Computing s.\n");
    syndrome_t syndrome;
    uint8_t e[R_BITS*2] = {0};
    uint8_t eBytes[N_SIZE] = {0};
    int rc;
    uint32_t u = 0; // For BIKE-1 and BIKE-2, u = 0 (i.e. syndrome must become a zero-vector)
    res = compute_syndrome(&syndrome, l_ct, l_sk); CHECK_STATUS(res);

    DMSG("  Decoding.\n");
#ifdef BIKE3
    u = T1/2; // For BIKE-3, u = t/2
#endif
    rc = decode(e, syndrome.raw, h0_compact, h1_compact, u);

    if (rc == 0)
    {
        DMSG("    Decoding result: success\n");
    }
    else
    {
        DMSG("    Decoding result: failure!\n");
    }

    // checking if error weight is exactly t:
    if (getHammingWeight(e, 2*R_BITS) != T1)
    {
        MSG("Error weight is not t\n");
    }

    convertBinaryToByte(eBytes, e, 2*R_BITS);
    res = get_ss(l_ss, eBytes);                CHECK_STATUS(res);

EXIT:

    DMSG("  Exit BIKE1_L1_crypto_kem_dec.\n");
    return res;
}
