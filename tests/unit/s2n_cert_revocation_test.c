/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/* Revocation decision parity — for all generated CRLs and stapled
 * OCSP responses, the zero-copy revocation validators reach the same accept /
 * reject decision (and, on reject, the same error class) as the libcrypto
 * reference path (X509_CRL_verify + X509_cmp_time + X509_CRL_get0_by_serial for
 * CRLs; OCSP_basic_verify + OCSP_resp_find_status + validity for OCSP).
 *
 * 
 *
 * Generator: libcrypto-signed CA + leaf generator with seeded xorshift PRNG
 * driving algorithm family, timestamp window, revoked-serial membership, and
 * signature tampering. Minimum 100 iterations. */

#include "tls/s2n_cert_revocation.h"

#include "crypto/s2n_pkey.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cert_parse.h"
#include "tls/s2n_crl.h"
#include "tls/s2n_x509_validator.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include <openssl/asn1.h>
    #include <openssl/bytestring.h>
    #include <openssl/evp.h>
    #include <openssl/x509.h>
    #include <openssl/x509v3.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <string.h>

    /* BoringSSL supports CBS but ships no <openssl/ocsp.h>. Mirror the library
     * (tls/s2n_x509_validator.c) and gate all OCSP usage on
     * S2N_OCSP_STAPLING_SUPPORTED, defined in tls/s2n_x509_validator.h. With
     * the header excluded, OCSP_NOCERTS is also undefined, so the OCSP arms
     * below compile out and only the CRL arms run. */
    #if S2N_OCSP_STAPLING_SUPPORTED
        #include <openssl/ocsp.h>
    #endif

    /* Valgrind slows these iteration-heavy arms down ~30x (each iteration
     * generates and signs fresh certificates/CRLs/OCSP responses), which can
     * overrun the ctest timeout. Scale the count down under Valgrind; every
     * other job runs the full count. */
    #define PROPERTY_TEST_ITERATIONS (getenv("S2N_VALGRIND") ? 10 : 100)

    /* Verification time used across the differential arms (fixed epoch second,
     * roughly 2021-09-13). Both the zero-copy validators and the libcrypto
     * oracle evaluate against this same instant. */
    #define S2N_TEST_VERIFY_TIME 1631500000

typedef enum {
    ALG_RSA_2048 = 0,
    ALG_ECDSA_P256,
    ALG_FAMILY_COUNT,
} s2n_test_alg_family;

/* Reproducible xorshift32 PRNG, matching the property tests. */
static uint32_t s2n_test_xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-function"
DEFINE_POINTER_CLEANUP_FUNC(EVP_PKEY *, EVP_PKEY_free);
DEFINE_POINTER_CLEANUP_FUNC(X509 *, X509_free);
DEFINE_POINTER_CLEANUP_FUNC(X509_CRL *, X509_CRL_free);
    #if S2N_OCSP_STAPLING_SUPPORTED
DEFINE_POINTER_CLEANUP_FUNC(OCSP_RESPONSE *, OCSP_RESPONSE_free);
DEFINE_POINTER_CLEANUP_FUNC(OCSP_BASICRESP *, OCSP_BASICRESP_free);
    #endif /* S2N_OCSP_STAPLING_SUPPORTED */
DEFINE_POINTER_CLEANUP_FUNC(ASN1_TIME *, ASN1_TIME_free);
DEFINE_POINTER_CLEANUP_FUNC(X509_STORE *, X509_STORE_free);
    #pragma GCC diagnostic pop

/* Only used by the OCSP oracle, which is gated on the signer-side OCSP APIs
 * (absent on awslc-fips-2022). */
    #ifdef OCSP_NOCERTS
static void s2n_test_sk_x509_free(STACK_OF(X509) **stack)
{
    if (stack != NULL && *stack != NULL) {
        sk_X509_free(*stack);
        *stack = NULL;
    }
}
    #endif /* OCSP_NOCERTS */

static const EVP_MD *s2n_test_get_digest(s2n_test_alg_family alg)
{
    (void) alg;
    return EVP_sha256();
}

static EVP_PKEY *s2n_test_generate_key(s2n_test_alg_family alg)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (alg == ALG_RSA_2048) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (ctx == NULL) {
            return NULL;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0
                || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0
                || EVP_PKEY_keygen(ctx, &key) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return NULL;
        }
        EVP_PKEY_CTX_free(ctx);
        return key;
    }

    /* ALG_ECDSA_P256 */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL) {
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0
            || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0
            || EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

/* Build a self-signed CA certificate. */
static X509 *s2n_test_create_ca(EVP_PKEY *ca_key, s2n_test_alg_family alg)
{
    X509 *cert = X509_new();
    if (cert == NULL) {
        return NULL;
    }
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), -365 * 24 * 3600);
    X509_gmtime_adj(X509_get_notAfter(cert), 10 * 365 * 24 * 3600);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *) "Revocation Test CA", -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_set_pubkey(cert, ca_key);

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_nconf_nid(NULL, &ctx, NID_basic_constraints,
            "critical,CA:TRUE");
    if (ext != NULL) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    ext = X509V3_EXT_nconf_nid(NULL, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    if (ext != NULL) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    if (X509_sign(cert, ca_key, s2n_test_get_digest(alg)) == 0) {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

/* Build a leaf certificate signed by the CA with the given serial. */
static X509 *s2n_test_create_leaf(EVP_PKEY *leaf_key, EVP_PKEY *ca_key,
        X509 *ca_cert, s2n_test_alg_family alg, long serial)
{
    X509 *cert = X509_new();
    if (cert == NULL) {
        return NULL;
    }
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    X509_gmtime_adj(X509_get_notBefore(cert), -30 * 24 * 3600);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *) "Revocation Test Leaf", -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));
    X509_set_pubkey(cert, leaf_key);

    if (X509_sign(cert, ca_key, s2n_test_get_digest(alg)) == 0) {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

static S2N_RESULT s2n_test_x509_to_der(X509 *cert, struct s2n_blob *der_out)
{
    unsigned char *buf = NULL;
    int len = i2d_X509(cert, &buf);
    RESULT_ENSURE_GT(len, 0);
    RESULT_GUARD_POSIX(s2n_alloc(der_out, (uint32_t) len));
    RESULT_CHECKED_MEMCPY(der_out->data, buf, len);
    OPENSSL_free(buf);
    return S2N_RESULT_OK;
}

/* --- CRL arm ------------------------------------------------------------- */

/* Build a signed CRL. `revoked_serial` (if > 0) is listed as revoked.
 * `this_offset` / `next_offset` are seconds relative to S2N_TEST_VERIFY_TIME
 * for thisUpdate / nextUpdate. `has_next` controls whether nextUpdate is set.
 * `tamper` flips a signature byte after signing. */
static S2N_RESULT s2n_test_build_crl(EVP_PKEY *ca_key, X509 *ca_cert,
        s2n_test_alg_family alg, long revoked_serial,
        int64_t this_offset, int64_t next_offset, bool has_next, bool tamper,
        struct s2n_blob *der_out)
{
    DEFER_CLEANUP(X509_CRL *crl = X509_CRL_new(), X509_CRL_free_pointer);
    RESULT_ENSURE_REF(crl);

    RESULT_GUARD_OSSL(X509_CRL_set_version(crl, 1), S2N_ERR_CERT_INVALID);
    RESULT_GUARD_OSSL(X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca_cert)),
            S2N_ERR_CERT_INVALID);

    DEFER_CLEANUP(ASN1_TIME *this_upd = ASN1_TIME_new(), ASN1_TIME_free_pointer);
    RESULT_ENSURE_REF(this_upd);
    RESULT_ENSURE_REF(ASN1_TIME_set(this_upd, (time_t) (S2N_TEST_VERIFY_TIME + this_offset)));
    RESULT_GUARD_OSSL(X509_CRL_set1_lastUpdate(crl, this_upd), S2N_ERR_CERT_INVALID);

    if (has_next) {
        DEFER_CLEANUP(ASN1_TIME *next_upd = ASN1_TIME_new(), ASN1_TIME_free_pointer);
        RESULT_ENSURE_REF(next_upd);
        RESULT_ENSURE_REF(ASN1_TIME_set(next_upd, (time_t) (S2N_TEST_VERIFY_TIME + next_offset)));
        RESULT_GUARD_OSSL(X509_CRL_set1_nextUpdate(crl, next_upd), S2N_ERR_CERT_INVALID);
    }

    if (revoked_serial > 0) {
        X509_REVOKED *rev = X509_REVOKED_new();
        RESULT_ENSURE_REF(rev);
        ASN1_INTEGER *ser = ASN1_INTEGER_new();
        if (ser == NULL) {
            X509_REVOKED_free(rev);
            RESULT_BAIL(S2N_ERR_CERT_INVALID);
        }
        ASN1_INTEGER_set(ser, revoked_serial);
        X509_REVOKED_set_serialNumber(rev, ser);
        ASN1_INTEGER_free(ser);

        DEFER_CLEANUP(ASN1_TIME *rev_time = ASN1_TIME_new(), ASN1_TIME_free_pointer);
        if (rev_time == NULL) {
            X509_REVOKED_free(rev);
            RESULT_BAIL(S2N_ERR_CERT_INVALID);
        }
        ASN1_TIME_set(rev_time, (time_t) (S2N_TEST_VERIFY_TIME - 100));
        X509_REVOKED_set_revocationDate(rev, rev_time);

        if (X509_CRL_add0_revoked(crl, rev) == 0) {
            X509_REVOKED_free(rev);
            RESULT_BAIL(S2N_ERR_CERT_INVALID);
        }
    }

    RESULT_GUARD_OSSL(X509_CRL_sort(crl), S2N_ERR_CERT_INVALID);
    /* X509_CRL_sign returns the signature length on success (0 on failure). */
    RESULT_ENSURE(X509_CRL_sign(crl, ca_key, s2n_test_get_digest(alg)) != 0, S2N_ERR_CERT_INVALID);

    unsigned char *buf = NULL;
    int len = i2d_X509_CRL(crl, &buf);
    RESULT_ENSURE_GT(len, 0);
    RESULT_GUARD_POSIX(s2n_alloc(der_out, (uint32_t) len));
    RESULT_CHECKED_MEMCPY(der_out->data, buf, len);
    OPENSSL_free(buf);

    if (tamper) {
        /* Flip a byte near the end (inside the signature BIT STRING) so the DER
         * still parses but the signature no longer verifies. */
        der_out->data[der_out->size - 1] ^= 0xFF;
    }
    return S2N_RESULT_OK;
}

/* libcrypto reference decision for the CRL arm. Returns S2N_RESULT_OK for
 * accept, or bails with the same error class the zero-copy path uses. */
static S2N_RESULT s2n_test_crl_oracle(struct s2n_blob *crl_der, EVP_PKEY *ca_key,
        long serial)
{
    const uint8_t *p = crl_der->data;
    DEFER_CLEANUP(X509_CRL *crl = d2i_X509_CRL(NULL, &p, (long) crl_der->size),
            X509_CRL_free_pointer);
    RESULT_ENSURE(crl != NULL, S2N_ERR_CERT_INVALID);

    /* Signature. */
    RESULT_ENSURE(X509_CRL_verify(crl, ca_key) == 1, S2N_ERR_CRL_SIGNATURE);

    /* thisUpdate: X509_cmp_time returns <0 if the time is in the past relative
     * to the compared instant. Mirror s2n_crl_validate_active. */
    time_t verify_time = (time_t) S2N_TEST_VERIFY_TIME;
    const ASN1_TIME *this_upd = X509_CRL_get0_lastUpdate(crl);
    RESULT_ENSURE(this_upd != NULL, S2N_ERR_CRL_INVALID_THIS_UPDATE);
    int cmp = X509_cmp_time(this_upd, &verify_time);
    RESULT_ENSURE(cmp != 0, S2N_ERR_CRL_INVALID_THIS_UPDATE);
    RESULT_ENSURE(cmp < 0, S2N_ERR_CRL_NOT_YET_VALID);

    /* nextUpdate. */
    const ASN1_TIME *next_upd = X509_CRL_get0_nextUpdate(crl);
    if (next_upd != NULL) {
        cmp = X509_cmp_time(next_upd, &verify_time);
        RESULT_ENSURE(cmp != 0, S2N_ERR_CRL_INVALID_NEXT_UPDATE);
        RESULT_ENSURE(cmp > 0, S2N_ERR_CRL_EXPIRED);
    }

    /* Serial membership. */
    ASN1_INTEGER *ser = ASN1_INTEGER_new();
    RESULT_ENSURE_REF(ser);
    ASN1_INTEGER_set(ser, serial);
    X509_REVOKED *entry = NULL;
    int found = X509_CRL_get0_by_serial(crl, &entry, ser);
    ASN1_INTEGER_free(ser);
    RESULT_ENSURE(found == 0, S2N_ERR_CERT_REVOKED);

    return S2N_RESULT_OK;
}

/* --- OCSP arm ------------------------------------------------------------ */

/* The OCSP arms build their own signed response fixtures, which requires the
 * signer-side OCSP APIs (OCSP_basic_sign, OCSP_response_create, ...). Older
 * aws-lc branches (awslc-fips-2022) only ship the verify-side APIs, so gate
 * the fixture-generating arms on OCSP_NOCERTS, which is defined alongside
 * the signer-side APIs. The CRL arms are unaffected. */
    #ifdef OCSP_NOCERTS

/* Build a signed OCSP response for `leaf` issued by `ca_cert`. */
static S2N_RESULT s2n_test_build_ocsp(EVP_PKEY *ca_key, X509 *ca_cert, X509 *leaf,
        s2n_test_alg_family alg, int cert_status, int64_t this_offset,
        int64_t next_offset, bool has_next, bool tamper, struct s2n_blob *der_out)
{
    DEFER_CLEANUP(OCSP_BASICRESP *basic = OCSP_BASICRESP_new(), OCSP_BASICRESP_free_pointer);
    RESULT_ENSURE_REF(basic);

    OCSP_CERTID *cert_id = OCSP_cert_to_id(EVP_sha1(), leaf, ca_cert);
    RESULT_ENSURE_REF(cert_id);

    DEFER_CLEANUP(ASN1_TIME *this_upd = ASN1_TIME_new(), ASN1_TIME_free_pointer);
    RESULT_ENSURE_REF(this_upd);
    RESULT_ENSURE_REF(ASN1_TIME_set(this_upd, (time_t) (S2N_TEST_VERIFY_TIME + this_offset)));

    ASN1_TIME *next_upd = NULL;
    DEFER_CLEANUP(ASN1_TIME *next_upd_owned = NULL, ASN1_TIME_free_pointer);
    if (has_next) {
        next_upd_owned = ASN1_TIME_new();
        RESULT_ENSURE_REF(next_upd_owned);
        RESULT_ENSURE_REF(ASN1_TIME_set(next_upd_owned, (time_t) (S2N_TEST_VERIFY_TIME + next_offset)));
        next_upd = next_upd_owned;
    }

    DEFER_CLEANUP(ASN1_TIME *rev_time = ASN1_TIME_new(), ASN1_TIME_free_pointer);
    RESULT_ENSURE_REF(rev_time);
    RESULT_ENSURE_REF(ASN1_TIME_set(rev_time, (time_t) (S2N_TEST_VERIFY_TIME - 1000)));

    OCSP_SINGLERESP *single = OCSP_basic_add1_status(basic, cert_id, cert_status,
            OCSP_REVOKED_STATUS_UNSPECIFIED, rev_time, this_upd, next_upd);
    OCSP_CERTID_free(cert_id);
    RESULT_ENSURE_REF(single);

    /* Sign the response directly with the CA (issuer) key; responderID byName
     * == CA subject, so the zero-copy path validates against the issuer key.
     * OCSP_NOCERTS suppresses embedding the signer certificate, so the response
     * signature BIT STRING is the final element of the DER encoding. The tamper
     * below flips the last byte, which then reliably lands inside the responder
     * signature (not an embedded certificate), so the corruption is detectable
     * by both the zero-copy responder-signature check and the libcrypto oracle. */
    RESULT_GUARD_OSSL(OCSP_basic_sign(basic, ca_cert, ca_key, s2n_test_get_digest(alg),
                              NULL, OCSP_NOCERTS),
            S2N_ERR_INVALID_OCSP_RESPONSE);

    DEFER_CLEANUP(OCSP_RESPONSE *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic),
            OCSP_RESPONSE_free_pointer);
    RESULT_ENSURE_REF(resp);

    unsigned char *buf = NULL;
    int len = i2d_OCSP_RESPONSE(resp, &buf);
    RESULT_ENSURE_GT(len, 0);
    RESULT_GUARD_POSIX(s2n_alloc(der_out, (uint32_t) len));
    RESULT_CHECKED_MEMCPY(der_out->data, buf, len);
    OPENSSL_free(buf);

    if (tamper) {
        der_out->data[der_out->size - 1] ^= 0xFF;
    }
    return S2N_RESULT_OK;
}

/* libcrypto reference decision for the OCSP arm. */
static S2N_RESULT s2n_test_ocsp_oracle(struct s2n_blob *ocsp_der, X509 *ca_cert,
        X509 *leaf, EVP_PKEY *ca_key)
{
    const uint8_t *p = ocsp_der->data;
    DEFER_CLEANUP(OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE(NULL, &p, (long) ocsp_der->size),
            OCSP_RESPONSE_free_pointer);
    RESULT_ENSURE(resp != NULL, S2N_ERR_INVALID_OCSP_RESPONSE);

    RESULT_ENSURE(OCSP_response_status(resp) == OCSP_RESPONSE_STATUS_SUCCESSFUL,
            S2N_ERR_CERT_UNTRUSTED);

    DEFER_CLEANUP(OCSP_BASICRESP *basic = OCSP_response_get1_basic(resp), OCSP_BASICRESP_free_pointer);
    RESULT_ENSURE(basic != NULL, S2N_ERR_INVALID_OCSP_RESPONSE);

    /* Verify the responder signature, mirroring the production OCSP path in
     * s2n_x509_validator_validate_cert_stapled_ocsp_response, which calls
     * OCSP_basic_verify(basic, cert_chain, trust_store, 0) with flags == 0 (NOT
     * OCSP_NOVERIFY): the responder signature IS verified. The earlier oracle
     * used OCSP_NOVERIFY, which skips signature verification and disagreed with
     * the signature-verifying zero-copy path on tampered responses. It also
     * passed a NULL store, which aws-lc's OCSP_basic_verify rejects outright.
     *
     * The response is signed directly by the issuer (responderID byName == CA
     * subject) and OCSP_NOCERTS suppressed the embedded signer cert, so we must
     * supply the CA both as the candidate signer stack (certs) and, via a
     * temporary trust store, as the trust anchor. flags == 0 then verifies the
     * responder signature exactly as production does. */
    (void) ca_key;

    DEFER_CLEANUP(X509_STORE *store = X509_STORE_new(), X509_STORE_free_pointer);
    RESULT_ENSURE_REF(store);
    RESULT_GUARD_OSSL(X509_STORE_add_cert(store, ca_cert), S2N_ERR_CERT_UNTRUSTED);

    DEFER_CLEANUP(STACK_OF(X509) *candidate_certs = sk_X509_new_null(), s2n_test_sk_x509_free);
    RESULT_ENSURE_REF(candidate_certs);
    RESULT_ENSURE(sk_X509_push(candidate_certs, ca_cert) > 0, S2N_ERR_CERT_UNTRUSTED);

    RESULT_ENSURE(OCSP_basic_verify(basic, candidate_certs, store, 0) == 1,
            S2N_ERR_CERT_UNTRUSTED);

    OCSP_CERTID *cert_id = OCSP_cert_to_id(EVP_sha1(), leaf, ca_cert);
    RESULT_ENSURE_REF(cert_id);
    int status = 0, reason = 0;
    ASN1_GENERALIZEDTIME *revtime = NULL, *thisupd = NULL, *nextupd = NULL;
    int find = OCSP_resp_find_status(basic, cert_id, &status, &reason, &revtime, &thisupd, &nextupd);
    OCSP_CERTID_free(cert_id);
    RESULT_ENSURE(find == 1, S2N_ERR_CERT_UNTRUSTED);

    /* Freshness, mirroring the current validator's thisUpdate/nextUpdate logic. */
    DEFER_CLEANUP(ASN1_TIME *now = ASN1_TIME_new(), ASN1_TIME_free_pointer);
    RESULT_ENSURE_REF(now);
    RESULT_ENSURE_REF(ASN1_TIME_set(now, (time_t) S2N_TEST_VERIFY_TIME));

    int pday = 0, psec = 0;
    RESULT_GUARD_OSSL(ASN1_TIME_diff(&pday, &psec, thisupd, now), S2N_ERR_CERT_UNTRUSTED);
    RESULT_ENSURE(pday >= 0 && psec >= 0, S2N_ERR_CERT_INVALID);
    if (nextupd != NULL) {
        RESULT_GUARD_OSSL(ASN1_TIME_diff(&pday, &psec, now, nextupd), S2N_ERR_CERT_UNTRUSTED);
        RESULT_ENSURE(pday >= 0 && psec >= 0, S2N_ERR_CERT_EXPIRED);
    } else {
        uint64_t after = (uint64_t) pday * (3600 * 24) + psec;
        RESULT_ENSURE(after < 3600, S2N_ERR_CERT_EXPIRED);
    }

    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            return S2N_RESULT_OK;
        case V_OCSP_CERTSTATUS_REVOKED:
            RESULT_BAIL(S2N_ERR_CERT_REVOKED);
        default:
            RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
    }
}

    #endif /* OCSP_NOCERTS */

/* Compare two S2N_RESULTs for decision parity: both OK, or both error with the
 * same errno. Uses s2n_errno captured immediately after each call. */
static void s2n_test_assert_parity(bool zc_ok, int zc_errno, bool ref_ok, int ref_errno)
{
    EXPECT_EQUAL(zc_ok, ref_ok);
    if (!zc_ok) {
        EXPECT_EQUAL(zc_errno, ref_errno);
    }
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if !S2N_LIBCRYPTO_SUPPORTS_CBS
    END_TEST();
#else

    /* CRL arm: differential decision parity for generated CRLs. */
    {
        for (uint32_t iter = 0; iter < PROPERTY_TEST_ITERATIONS; iter++) {
            uint32_t prng = iter + 1;

            s2n_test_alg_family alg = s2n_test_xorshift32(&prng) % ALG_FAMILY_COUNT;
            long leaf_serial = 100 + (long) (s2n_test_xorshift32(&prng) % 900);

            DEFER_CLEANUP(struct s2n_pkey ca_pub = { 0 }, s2n_pkey_free);
            EVP_PKEY *ca_key = s2n_test_generate_key(alg);
            EXPECT_NOT_NULL(ca_key);
            X509 *ca_cert = s2n_test_create_ca(ca_key, alg);
            EXPECT_NOT_NULL(ca_cert);

            EVP_PKEY *leaf_key = s2n_test_generate_key(alg);
            EXPECT_NOT_NULL(leaf_key);
            X509 *leaf = s2n_test_create_leaf(leaf_key, ca_key, ca_cert, alg, leaf_serial);
            EXPECT_NOT_NULL(leaf);

            /* Randomize the scenario dimensions. */
            uint32_t r = s2n_test_xorshift32(&prng);
            bool revoke_this = (r & 1);             /* list the leaf serial */
            bool tamper = ((r >> 1) & 1);           /* corrupt the signature */
            bool has_next = ((r >> 2) & 1) || true; /* usually present */
            int time_case = (r >> 3) % 3;           /* 0 valid, 1 not-yet, 2 expired */

            int64_t this_offset = -3600;
            int64_t next_offset = 3600;
            if (time_case == 1) {
                this_offset = 3600; /* thisUpdate in the future */
                next_offset = 7200;
            } else if (time_case == 2) {
                this_offset = -7200;
                next_offset = -3600; /* nextUpdate in the past */
            }

            long revoked_serial = revoke_this ? leaf_serial : 0;

            struct s2n_blob crl_der = { 0 };
            EXPECT_OK(s2n_test_build_crl(ca_key, ca_cert, alg, revoked_serial,
                    this_offset, next_offset, has_next, tamper, &crl_der));

            /* Materialize the CA public key for the zero-copy signature check. */
            struct s2n_blob leaf_serial_blob = { 0 };
            /* Extract the leaf's serial INTEGER contents via the zero-copy parser. */
            struct s2n_blob leaf_der = { 0 };
            EXPECT_OK(s2n_test_x509_to_der(leaf, &leaf_der));
            struct s2n_cert_span_view leaf_view = { 0 };
            EXPECT_OK(s2n_cert_span_view_parse(&leaf_view, &leaf_der));
            EXPECT_SUCCESS(s2n_blob_init(&leaf_serial_blob, leaf_view.serial.data, leaf_view.serial.size));

            /* Build the s2n_pkey from the CA's SPKI (reuse the parser's SPKI span). */
            struct s2n_blob ca_der = { 0 };
            EXPECT_OK(s2n_test_x509_to_der(ca_cert, &ca_der));
            struct s2n_cert_span_view ca_view = { 0 };
            EXPECT_OK(s2n_cert_span_view_parse(&ca_view, &ca_der));

            s2n_pkey_type ca_type = S2N_PKEY_TYPE_UNKNOWN;
            EXPECT_OK(s2n_pkey_from_x509(ca_cert, &ca_pub, &ca_type));

            /* Zero-copy decision. */
            s2n_errno = 0;
            bool zc_ok = s2n_result_is_ok(s2n_crl_validate(&crl_der, &ca_pub,
                    &leaf_serial_blob, S2N_TEST_VERIFY_TIME));
            int zc_errno = s2n_errno;

            /* Reference decision. */
            s2n_errno = 0;
            bool ref_ok = s2n_result_is_ok(s2n_test_crl_oracle(&crl_der, ca_key, leaf_serial));
            int ref_errno = s2n_errno;

            s2n_test_assert_parity(zc_ok, zc_errno, ref_ok, ref_errno);

            EXPECT_SUCCESS(s2n_free(&crl_der));
            EXPECT_SUCCESS(s2n_free(&leaf_der));
            EXPECT_SUCCESS(s2n_free(&ca_der));
            EVP_PKEY_free(ca_key);
            EVP_PKEY_free(leaf_key);
            X509_free(ca_cert);
            X509_free(leaf);
        }
    }

    /* OCSP arm: differential decision parity for generated stapled responses.
     * Gated on the signer-side OCSP APIs needed to build the fixtures (absent
     * on awslc-fips-2022). */
    #ifdef OCSP_NOCERTS
    {
        for (uint32_t iter = 0; iter < PROPERTY_TEST_ITERATIONS; iter++) {
            uint32_t prng = 0x9e3779b9u ^ (iter + 1);

            s2n_test_alg_family alg = s2n_test_xorshift32(&prng) % ALG_FAMILY_COUNT;

            EVP_PKEY *ca_key = s2n_test_generate_key(alg);
            EXPECT_NOT_NULL(ca_key);
            X509 *ca_cert = s2n_test_create_ca(ca_key, alg);
            EXPECT_NOT_NULL(ca_cert);

            EVP_PKEY *leaf_key = s2n_test_generate_key(alg);
            EXPECT_NOT_NULL(leaf_key);
            X509 *leaf = s2n_test_create_leaf(leaf_key, ca_key, ca_cert, alg, 42);
            EXPECT_NOT_NULL(leaf);

            uint32_t r = s2n_test_xorshift32(&prng);
            int status_case = r % 3; /* 0 good, 1 revoked, 2 unknown */
            bool tamper = ((r >> 2) & 1);
            bool has_next = ((r >> 3) & 1);
            int time_case = (r >> 4) % 3; /* 0 fresh, 1 future thisUpdate, 2 expired */

            int cert_status = V_OCSP_CERTSTATUS_GOOD;
            if (status_case == 1) {
                cert_status = V_OCSP_CERTSTATUS_REVOKED;
            } else if (status_case == 2) {
                cert_status = V_OCSP_CERTSTATUS_UNKNOWN;
            }

            int64_t this_offset = -3600;
            int64_t next_offset = 3600;
            if (time_case == 1) {
                this_offset = 3600;
                next_offset = 7200;
            } else if (time_case == 2) {
                this_offset = -7200;
                next_offset = -3600;
                has_next = true; /* need nextUpdate present to express "expired" */
            }

            struct s2n_blob ocsp_der = { 0 };
            EXPECT_OK(s2n_test_build_ocsp(ca_key, ca_cert, leaf, alg, cert_status,
                    this_offset, next_offset, has_next, tamper, &ocsp_der));

            /* Parse leaf/issuer span views for the zero-copy validator. */
            struct s2n_blob leaf_der = { 0 };
            EXPECT_OK(s2n_test_x509_to_der(leaf, &leaf_der));
            struct s2n_cert_span_view leaf_view = { 0 };
            EXPECT_OK(s2n_cert_span_view_parse(&leaf_view, &leaf_der));

            struct s2n_blob ca_der = { 0 };
            EXPECT_OK(s2n_test_x509_to_der(ca_cert, &ca_der));
            struct s2n_cert_span_view ca_view = { 0 };
            EXPECT_OK(s2n_cert_span_view_parse(&ca_view, &ca_der));

            s2n_errno = 0;
            bool zc_ok = s2n_result_is_ok(s2n_ocsp_validate(&ocsp_der, &leaf_view,
                    &ca_view, S2N_TEST_VERIFY_TIME));
            int zc_errno = s2n_errno;

            s2n_errno = 0;
            bool ref_ok = s2n_result_is_ok(s2n_test_ocsp_oracle(&ocsp_der, ca_cert, leaf, ca_key));
            int ref_errno = s2n_errno;

            s2n_test_assert_parity(zc_ok, zc_errno, ref_ok, ref_errno);

            EXPECT_SUCCESS(s2n_free(&ocsp_der));
            EXPECT_SUCCESS(s2n_free(&leaf_der));
            EXPECT_SUCCESS(s2n_free(&ca_der));
            EVP_PKEY_free(ca_key);
            EVP_PKEY_free(leaf_key);
            X509_free(ca_cert);
            X509_free(leaf);
        }
    }
    #endif /* OCSP_NOCERTS */

    /* Targeted fixtures: explicit revoked-serial, bad-signature, and
     * timestamp-window cases with pinned expected error codes. */
    {
        EVP_PKEY *ca_key = s2n_test_generate_key(ALG_ECDSA_P256);
        EXPECT_NOT_NULL(ca_key);
        X509 *ca_cert = s2n_test_create_ca(ca_key, ALG_ECDSA_P256);
        EXPECT_NOT_NULL(ca_cert);
        EVP_PKEY *leaf_key = s2n_test_generate_key(ALG_ECDSA_P256);
        EXPECT_NOT_NULL(leaf_key);
        X509 *leaf = s2n_test_create_leaf(leaf_key, ca_key, ca_cert, ALG_ECDSA_P256, 777);
        EXPECT_NOT_NULL(leaf);

        DEFER_CLEANUP(struct s2n_pkey ca_pub = { 0 }, s2n_pkey_free);
        s2n_pkey_type ca_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_pkey_from_x509(ca_cert, &ca_pub, &ca_type));

        uint8_t serial_777[] = { 0x03, 0x09 }; /* 777 = 0x0309 */
        struct s2n_blob serial = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&serial, serial_777, sizeof(serial_777)));

        /* Fixture A: leaf serial revoked -> S2N_ERR_CERT_REVOKED. */
        {
            struct s2n_blob crl = { 0 };
            EXPECT_OK(s2n_test_build_crl(ca_key, ca_cert, ALG_ECDSA_P256, 777,
                    -3600, 3600, true, false, &crl));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_crl_validate(&crl, &ca_pub, &serial, S2N_TEST_VERIFY_TIME),
                    S2N_ERR_CERT_REVOKED);
            EXPECT_SUCCESS(s2n_free(&crl));
        }

        /* Fixture B: not-revoked serial -> accept. */
        {
            struct s2n_blob crl = { 0 };
            EXPECT_OK(s2n_test_build_crl(ca_key, ca_cert, ALG_ECDSA_P256, 0,
                    -3600, 3600, true, false, &crl));
            EXPECT_OK(s2n_crl_validate(&crl, &ca_pub, &serial, S2N_TEST_VERIFY_TIME));
            EXPECT_SUCCESS(s2n_free(&crl));
        }

        /* Fixture C: tampered signature -> S2N_ERR_CRL_SIGNATURE. */
        {
            struct s2n_blob crl = { 0 };
            EXPECT_OK(s2n_test_build_crl(ca_key, ca_cert, ALG_ECDSA_P256, 0,
                    -3600, 3600, true, true, &crl));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_crl_validate(&crl, &ca_pub, &serial, S2N_TEST_VERIFY_TIME),
                    S2N_ERR_CRL_SIGNATURE);
            EXPECT_SUCCESS(s2n_free(&crl));
        }

        /* Fixture D: thisUpdate in the future -> S2N_ERR_CRL_NOT_YET_VALID. */
        {
            struct s2n_blob crl = { 0 };
            EXPECT_OK(s2n_test_build_crl(ca_key, ca_cert, ALG_ECDSA_P256, 0,
                    3600, 7200, true, false, &crl));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_crl_validate(&crl, &ca_pub, &serial, S2N_TEST_VERIFY_TIME),
                    S2N_ERR_CRL_NOT_YET_VALID);
            EXPECT_SUCCESS(s2n_free(&crl));
        }

        /* Fixture E: nextUpdate in the past -> S2N_ERR_CRL_EXPIRED. */
        {
            struct s2n_blob crl = { 0 };
            EXPECT_OK(s2n_test_build_crl(ca_key, ca_cert, ALG_ECDSA_P256, 0,
                    -7200, -3600, true, false, &crl));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_crl_validate(&crl, &ca_pub, &serial, S2N_TEST_VERIFY_TIME),
                    S2N_ERR_CRL_EXPIRED);
            EXPECT_SUCCESS(s2n_free(&crl));
        }

    /* OCSP fixtures reuse the same leaf/issuer span views. Gated on the
     * signer-side OCSP APIs needed to build the fixtures (absent on
     * awslc-fips-2022). */
    #ifdef OCSP_NOCERTS
        struct s2n_blob leaf_der = { 0 };
        EXPECT_OK(s2n_test_x509_to_der(leaf, &leaf_der));
        struct s2n_cert_span_view leaf_view = { 0 };
        EXPECT_OK(s2n_cert_span_view_parse(&leaf_view, &leaf_der));
        struct s2n_blob ca_der = { 0 };
        EXPECT_OK(s2n_test_x509_to_der(ca_cert, &ca_der));
        struct s2n_cert_span_view ca_view = { 0 };
        EXPECT_OK(s2n_cert_span_view_parse(&ca_view, &ca_der));

        /* Fixture F: OCSP good -> accept. */
        {
            struct s2n_blob resp = { 0 };
            EXPECT_OK(s2n_test_build_ocsp(ca_key, ca_cert, leaf, ALG_ECDSA_P256,
                    V_OCSP_CERTSTATUS_GOOD, -3600, 3600, true, false, &resp));
            EXPECT_OK(s2n_ocsp_validate(&resp, &leaf_view, &ca_view, S2N_TEST_VERIFY_TIME));
            EXPECT_SUCCESS(s2n_free(&resp));
        }

        /* Fixture G: OCSP revoked -> S2N_ERR_CERT_REVOKED. */
        {
            struct s2n_blob resp = { 0 };
            EXPECT_OK(s2n_test_build_ocsp(ca_key, ca_cert, leaf, ALG_ECDSA_P256,
                    V_OCSP_CERTSTATUS_REVOKED, -3600, 3600, true, false, &resp));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ocsp_validate(&resp, &leaf_view, &ca_view, S2N_TEST_VERIFY_TIME),
                    S2N_ERR_CERT_REVOKED);
            EXPECT_SUCCESS(s2n_free(&resp));
        }

        /* Fixture H: OCSP tampered signature -> S2N_ERR_CERT_UNTRUSTED. */
        {
            struct s2n_blob resp = { 0 };
            EXPECT_OK(s2n_test_build_ocsp(ca_key, ca_cert, leaf, ALG_ECDSA_P256,
                    V_OCSP_CERTSTATUS_GOOD, -3600, 3600, true, true, &resp));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ocsp_validate(&resp, &leaf_view, &ca_view, S2N_TEST_VERIFY_TIME),
                    S2N_ERR_CERT_UNTRUSTED);
            EXPECT_SUCCESS(s2n_free(&resp));
        }

        /* Fixture I: OCSP expired (nextUpdate in the past) -> S2N_ERR_CERT_EXPIRED. */
        {
            struct s2n_blob resp = { 0 };
            EXPECT_OK(s2n_test_build_ocsp(ca_key, ca_cert, leaf, ALG_ECDSA_P256,
                    V_OCSP_CERTSTATUS_GOOD, -7200, -3600, true, false, &resp));
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_ocsp_validate(&resp, &leaf_view, &ca_view, S2N_TEST_VERIFY_TIME),
                    S2N_ERR_CERT_EXPIRED);
            EXPECT_SUCCESS(s2n_free(&resp));
        }

        EXPECT_SUCCESS(s2n_free(&leaf_der));
        EXPECT_SUCCESS(s2n_free(&ca_der));
    #endif /* OCSP_NOCERTS */
        EVP_PKEY_free(ca_key);
        EVP_PKEY_free(leaf_key);
        X509_free(ca_cert);
        X509_free(leaf);
    }

    /* s2n_x509_validator_check_crl wiring tests.
     * Exercises the CRL lookup-callback bridge: the function receives a
     * crl_lookup_list entry (populated by the callback) and routes the
     * callback-delivered X509_CRL through the zero-copy s2n_crl_validate. */
    {
        EVP_PKEY *ca_key = s2n_test_generate_key(ALG_ECDSA_P256);
        EXPECT_NOT_NULL(ca_key);
        X509 *ca_cert = s2n_test_create_ca(ca_key, ALG_ECDSA_P256);
        EXPECT_NOT_NULL(ca_cert);
        EVP_PKEY *leaf_key = s2n_test_generate_key(ALG_ECDSA_P256);
        EXPECT_NOT_NULL(leaf_key);
        X509 *leaf = s2n_test_create_leaf(leaf_key, ca_key, ca_cert, ALG_ECDSA_P256, 555);
        EXPECT_NOT_NULL(leaf);

        DEFER_CLEANUP(struct s2n_pkey ca_pub = { 0 }, s2n_pkey_free);
        s2n_pkey_type ca_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_pkey_from_x509(ca_cert, &ca_pub, &ca_type));

        /* Extract the leaf's serial from the cert. */
        struct s2n_blob leaf_der = { 0 };
        EXPECT_OK(s2n_test_x509_to_der(leaf, &leaf_der));
        struct s2n_cert_span_view leaf_view = { 0 };
        EXPECT_OK(s2n_cert_span_view_parse(&leaf_view, &leaf_der));
        struct s2n_blob serial = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&serial, leaf_view.serial.data, leaf_view.serial.size));

        /* Wiring test J: NULL CRL (callback declined) -> S2N_ERR_CRL_LOOKUP_FAILED. */
        {
            struct s2n_crl_lookup lookup = { .status = FINISHED, .cert = leaf, .cert_idx = 0, .crl = NULL };
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_x509_validator_check_crl(&lookup, &ca_pub, &serial, S2N_TEST_VERIFY_TIME),
                    S2N_ERR_CRL_LOOKUP_FAILED);
        }

        /* Wiring test K: valid CRL, leaf not revoked -> accept. */
        {
            /* Build a CRL via libcrypto. */
            X509_CRL *x509_crl = X509_CRL_new();
            EXPECT_NOT_NULL(x509_crl);
            EXPECT_TRUE(X509_CRL_set_version(x509_crl, 1));
            EXPECT_TRUE(X509_CRL_set_issuer_name(x509_crl, X509_get_subject_name(ca_cert)));
            ASN1_TIME *this_upd = ASN1_TIME_new();
            EXPECT_NOT_NULL(this_upd);
            ASN1_TIME_set(this_upd, (time_t) (S2N_TEST_VERIFY_TIME - 3600));
            EXPECT_TRUE(X509_CRL_set1_lastUpdate(x509_crl, this_upd));
            ASN1_TIME *next_upd = ASN1_TIME_new();
            EXPECT_NOT_NULL(next_upd);
            ASN1_TIME_set(next_upd, (time_t) (S2N_TEST_VERIFY_TIME + 3600));
            EXPECT_TRUE(X509_CRL_set1_nextUpdate(x509_crl, next_upd));
            ASN1_TIME_free(this_upd);
            ASN1_TIME_free(next_upd);
            EXPECT_TRUE(X509_CRL_sort(x509_crl));
            EXPECT_TRUE(X509_CRL_sign(x509_crl, ca_key, EVP_sha256()) != 0);

            struct s2n_crl crl_obj = { .crl = x509_crl };
            struct s2n_crl_lookup lookup = { .status = FINISHED, .cert = leaf, .cert_idx = 0, .crl = &crl_obj };

            EXPECT_OK(s2n_x509_validator_check_crl(&lookup, &ca_pub, &serial, S2N_TEST_VERIFY_TIME));
            X509_CRL_free(x509_crl);
        }

        /* Wiring test L: CRL lists the leaf serial -> S2N_ERR_CERT_REVOKED. */
        {
            X509_CRL *x509_crl = X509_CRL_new();
            EXPECT_NOT_NULL(x509_crl);
            EXPECT_TRUE(X509_CRL_set_version(x509_crl, 1));
            EXPECT_TRUE(X509_CRL_set_issuer_name(x509_crl, X509_get_subject_name(ca_cert)));
            ASN1_TIME *this_upd = ASN1_TIME_new();
            EXPECT_NOT_NULL(this_upd);
            ASN1_TIME_set(this_upd, (time_t) (S2N_TEST_VERIFY_TIME - 3600));
            EXPECT_TRUE(X509_CRL_set1_lastUpdate(x509_crl, this_upd));
            ASN1_TIME *next_upd = ASN1_TIME_new();
            EXPECT_NOT_NULL(next_upd);
            ASN1_TIME_set(next_upd, (time_t) (S2N_TEST_VERIFY_TIME + 3600));
            EXPECT_TRUE(X509_CRL_set1_nextUpdate(x509_crl, next_upd));
            ASN1_TIME_free(this_upd);
            ASN1_TIME_free(next_upd);

            /* Revoke serial 555. */
            X509_REVOKED *rev = X509_REVOKED_new();
            EXPECT_NOT_NULL(rev);
            ASN1_INTEGER *ser = ASN1_INTEGER_new();
            EXPECT_NOT_NULL(ser);
            ASN1_INTEGER_set(ser, 555);
            X509_REVOKED_set_serialNumber(rev, ser);
            ASN1_INTEGER_free(ser);
            ASN1_TIME *rev_time = ASN1_TIME_new();
            EXPECT_NOT_NULL(rev_time);
            ASN1_TIME_set(rev_time, (time_t) (S2N_TEST_VERIFY_TIME - 100));
            X509_REVOKED_set_revocationDate(rev, rev_time);
            ASN1_TIME_free(rev_time);
            EXPECT_TRUE(X509_CRL_add0_revoked(x509_crl, rev));
            EXPECT_TRUE(X509_CRL_sort(x509_crl));
            EXPECT_TRUE(X509_CRL_sign(x509_crl, ca_key, EVP_sha256()) != 0);

            struct s2n_crl crl_obj = { .crl = x509_crl };
            struct s2n_crl_lookup lookup = { .status = FINISHED, .cert = leaf, .cert_idx = 0, .crl = &crl_obj };

            EXPECT_ERROR_WITH_ERRNO(
                    s2n_x509_validator_check_crl(&lookup, &ca_pub, &serial, S2N_TEST_VERIFY_TIME),
                    S2N_ERR_CERT_REVOKED);
            X509_CRL_free(x509_crl);
        }

        /* Wiring test M: tampered CRL signature -> S2N_ERR_CRL_SIGNATURE. */
        {
            X509_CRL *x509_crl = X509_CRL_new();
            EXPECT_NOT_NULL(x509_crl);
            EXPECT_TRUE(X509_CRL_set_version(x509_crl, 1));
            EXPECT_TRUE(X509_CRL_set_issuer_name(x509_crl, X509_get_subject_name(ca_cert)));
            ASN1_TIME *this_upd = ASN1_TIME_new();
            EXPECT_NOT_NULL(this_upd);
            ASN1_TIME_set(this_upd, (time_t) (S2N_TEST_VERIFY_TIME - 3600));
            EXPECT_TRUE(X509_CRL_set1_lastUpdate(x509_crl, this_upd));
            ASN1_TIME *next_upd = ASN1_TIME_new();
            EXPECT_NOT_NULL(next_upd);
            ASN1_TIME_set(next_upd, (time_t) (S2N_TEST_VERIFY_TIME + 3600));
            EXPECT_TRUE(X509_CRL_set1_nextUpdate(x509_crl, next_upd));
            ASN1_TIME_free(this_upd);
            ASN1_TIME_free(next_upd);
            EXPECT_TRUE(X509_CRL_sort(x509_crl));
            /* Sign with the wrong key (leaf_key instead of ca_key). */
            EXPECT_TRUE(X509_CRL_sign(x509_crl, leaf_key, EVP_sha256()) != 0);

            struct s2n_crl crl_obj = { .crl = x509_crl };
            struct s2n_crl_lookup lookup = { .status = FINISHED, .cert = leaf, .cert_idx = 0, .crl = &crl_obj };

            EXPECT_ERROR_WITH_ERRNO(
                    s2n_x509_validator_check_crl(&lookup, &ca_pub, &serial, S2N_TEST_VERIFY_TIME),
                    S2N_ERR_CRL_SIGNATURE);
            X509_CRL_free(x509_crl);
        }

        EXPECT_SUCCESS(s2n_free(&leaf_der));
        EVP_PKEY_free(ca_key);
        EVP_PKEY_free(leaf_key);
        X509_free(ca_cert);
        X509_free(leaf);
    }

    END_TEST();
#endif     /* S2N_LIBCRYPTO_SUPPORTS_CBS */
}
