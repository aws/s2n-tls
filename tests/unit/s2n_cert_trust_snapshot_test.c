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

/* Trust-store snapshot round-trip — for all anchor sets loaded
 * into the trust store (via PEM string, CA file, CA directory), the
 * Trust_Store_Bridge snapshot contains exactly the DER encodings (per i2d_X509)
 * of the store's certificates, as a multiset.
 *
 * 
 *
 * Generator: seeded-PRNG anchor-set generator (1-5 self-signed CA certs with
 * distinct subjects and random algorithm families). Minimum 100 iterations. */

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_x509_validator.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include <openssl/evp.h>
    #include <openssl/pem.h>
    #include <openssl/x509.h>
    #include <pthread.h>
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>

    #include "tls/s2n_cert_parse.h"
    #include "tls/s2n_cert_path.h"

    /* Valgrind slows this test down ~30x, risking the ctest timeout, so scale
     * down under Valgrind; every other job runs the full count. */
    #define PROPERTY_TEST_ITERATIONS (getenv("S2N_VALGRIND") ? 10 : 100)
    #define MAX_ANCHORS_PER_SET      5

/* Seeded PRNG (SplitMix64) so runs are deterministic and reproducible. */
static uint64_t s2n_test_prng_state = 0;

static uint64_t s2n_test_prng_next(void)
{
    s2n_test_prng_state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = s2n_test_prng_state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

typedef enum {
    ALG_RSA_2048 = 0,
    ALG_ECDSA_P256,
    ALG_ECDSA_P384,
    ALG_FAMILY_COUNT,
} s2n_test_alg_family;

static EVP_PKEY *s2n_test_generate_key(s2n_test_alg_family alg)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (alg == ALG_RSA_2048) {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0
                || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0
                || EVP_PKEY_keygen(ctx, &key) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return NULL;
        }
        EVP_PKEY_CTX_free(ctx);
        return key;
    }

    int nid = (alg == ALG_ECDSA_P256) ? NID_X9_62_prime256v1 : NID_secp384r1;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0
            || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0
            || EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

/* Create a self-signed CA certificate with a distinct CN. Caller frees. */
static X509 *s2n_test_create_ca_cert(EVP_PKEY *ca_key, s2n_test_alg_family alg,
        uint64_t unique)
{
    X509 *cert = X509_new();
    if (cert == NULL) {
        return NULL;
    }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long) (unique & 0x7FFFFFFF));
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600);

    X509_NAME *name = X509_get_subject_name(cert);
    char cn[64] = { 0 };
    snprintf(cn, sizeof(cn), "Test Snapshot CA %llu", (unsigned long long) unique);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *) cn, -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_set_pubkey(cert, ca_key);

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_nconf_nid(NULL, &ctx,
            NID_basic_constraints, "critical,CA:TRUE");
    if (ext != NULL) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    const EVP_MD *md = (alg == ALG_ECDSA_P384) ? EVP_sha384() : EVP_sha256();
    if (X509_sign(cert, ca_key, md) == 0) {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

/* Collect the i2d_X509 DER of every X509 in the store into der_list (each
 * allocated with s2n_alloc). Returns the count. */
static S2N_RESULT s2n_test_store_ders(X509_STORE *store,
        struct s2n_blob *der_list, uint32_t max, uint32_t *count_out)
{
    STACK_OF(X509_OBJECT) *objects = X509_STORE_get0_objects(store);
    RESULT_ENSURE_REF(objects);
    uint32_t count = 0;
    int num = sk_X509_OBJECT_num(objects);
    for (int i = 0; i < num; i++) {
        X509_OBJECT *object = sk_X509_OBJECT_value(objects, i);
        if (object == NULL || X509_OBJECT_get_type(object) != X509_LU_X509) {
            continue;
        }
        X509 *cert = X509_OBJECT_get0_X509(object);
        RESULT_ENSURE_REF(cert);
        RESULT_ENSURE_LT(count, max);

        unsigned char *buf = NULL;
        int len = i2d_X509(cert, &buf);
        RESULT_ENSURE_GT(len, 0);
        RESULT_GUARD_POSIX(s2n_alloc(&der_list[count], (uint32_t) len));
        RESULT_CHECKED_MEMCPY(der_list[count].data, buf, len);
        OPENSSL_free(buf);
        count++;
    }
    *count_out = count;
    return S2N_RESULT_OK;
}

/* Assert two DER blob lists are equal as multisets. */
static S2N_RESULT s2n_test_assert_multiset_equal(
        const struct s2n_trust_anchor *anchors, uint32_t anchor_count,
        struct s2n_blob *expected, uint32_t expected_count)
{
    RESULT_ENSURE_EQ(anchor_count, expected_count);

    bool matched[MAX_ANCHORS_PER_SET] = { 0 };
    for (uint32_t i = 0; i < anchor_count; i++) {
        const struct s2n_blob *a = &anchors[i].der;
        bool found = false;
        for (uint32_t j = 0; j < expected_count; j++) {
            if (matched[j]) {
                continue;
            }
            if (a->size == expected[j].size
                    && memcmp(a->data, expected[j].data, a->size) == 0) {
                matched[j] = true;
                found = true;
                break;
            }
        }
        RESULT_ENSURE(found, S2N_ERR_SAFETY);
    }
    return S2N_RESULT_OK;
}

typedef enum {
    LOAD_PEM_STRING = 0,
    LOAD_CA_FILE,
    LOAD_CA_DIR,
    LOAD_METHOD_COUNT,
} s2n_test_load_method;

/* Load `count` freshly generated self-signed CAs into `store` via the PEM
 * string API. certs_out/keys_out receive the generated objects for cleanup. */
static S2N_RESULT s2n_test_populate_store(struct s2n_x509_trust_store *store,
        uint32_t count, uint64_t seed, X509 **certs_out, EVP_PKEY **keys_out)
{
    BIO *bio = BIO_new(BIO_s_mem());
    RESULT_ENSURE_REF(bio);
    for (uint32_t i = 0; i < count; i++) {
        s2n_test_alg_family alg = (s2n_test_alg_family) ((seed + i) % ALG_FAMILY_COUNT);
        keys_out[i] = s2n_test_generate_key(alg);
        RESULT_ENSURE_REF(keys_out[i]);
        certs_out[i] = s2n_test_create_ca_cert(keys_out[i], alg, (seed << 8) | i);
        RESULT_ENSURE_REF(certs_out[i]);
        RESULT_ENSURE_EQ(PEM_write_bio_X509(bio, certs_out[i]), 1);
    }
    char *pem_data = NULL;
    long pem_len = BIO_get_mem_data(bio, &pem_data);
    RESULT_ENSURE_GT(pem_len, 0);
    char *pem_str = malloc(pem_len + 1);
    if (pem_str == NULL) {
        BIO_free(bio);
        RESULT_BAIL(S2N_ERR_ALLOC);
    }
    memcpy(pem_str, pem_data, pem_len);
    pem_str[pem_len] = '\0';
    int rc = s2n_x509_trust_store_add_pem(store, pem_str);
    free(pem_str);
    BIO_free(bio);
    RESULT_ENSURE_EQ(rc, 0);
    return S2N_RESULT_OK;
}

/* Arguments for the TSan reader threads: each thread acquires, reads, and
 * releases the shared snapshot repeatedly. */
struct s2n_test_reader_args {
    struct s2n_x509_trust_store *store;
    uint32_t iterations;
    uint32_t observed_count;
};

static void *s2n_test_snapshot_reader(void *arg)
{
    struct s2n_test_reader_args *args = (struct s2n_test_reader_args *) arg;
    for (uint32_t i = 0; i < args->iterations; i++) {
        struct s2n_trust_anchor_snapshot *snapshot = NULL;
        if (s2n_result_is_error(s2n_x509_trust_store_snapshot_acquire(args->store, &snapshot))) {
            return NULL;
        }
        /* Read the immutable snapshot: touch every anchor's spans. Any data
         * race here (e.g. a concurrent build mutating the array) is what TSan
         * is meant to catch. */
        uint32_t sum = 0;
        for (uint32_t a = 0; a < snapshot->count; a++) {
            sum += (uint32_t) snapshot->anchors[a].der.size;
            sum += (uint32_t) snapshot->anchors[a].parsed.raw.size;
        }
        args->observed_count = snapshot->count;
        (void) sum;
        if (s2n_result_is_error(s2n_x509_trust_store_snapshot_release(args->store, snapshot))) {
            return NULL;
        }
    }
    return arg;
}

    #define S2N_TEST_NUM_READERS 8

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* Trust-store snapshot round-trip — the snapshot's anchor DER
     * multiset equals the store's i2d_X509 multiset, for PEM string, CA file,
     * and CA directory loading. */
    for (uint32_t iter = 0; iter < PROPERTY_TEST_ITERATIONS; iter++) {
        s2n_test_prng_state = 0xC0FFEE00ULL + iter;

        /* Generate an anchor set: 1-5 distinct self-signed CA certs. */
        uint32_t anchor_count = (uint32_t) (s2n_test_prng_next() % MAX_ANCHORS_PER_SET) + 1;
        s2n_test_load_method method = (s2n_test_load_method) (iter % LOAD_METHOD_COUNT);

        X509 *certs[MAX_ANCHORS_PER_SET] = { 0 };
        EVP_PKEY *keys[MAX_ANCHORS_PER_SET] = { 0 };
        for (uint32_t i = 0; i < anchor_count; i++) {
            s2n_test_alg_family alg = (s2n_test_alg_family) (s2n_test_prng_next() % ALG_FAMILY_COUNT);
            keys[i] = s2n_test_generate_key(alg);
            EXPECT_NOT_NULL(keys[i]);
            /* Unique subject per cert so the store never dedups. */
            certs[i] = s2n_test_create_ca_cert(keys[i], alg, ((uint64_t) iter << 8) | i);
            EXPECT_NOT_NULL(certs[i]);
        }

        struct s2n_x509_trust_store trust_store = { 0 };
        s2n_x509_trust_store_init_empty(&trust_store);

        char tmp_path[] = "/tmp/s2n_snap_XXXXXX";
        /* Paths of files created inside the CA directory, for cleanup. */
        char dir_files[MAX_ANCHORS_PER_SET][256] = { { 0 } };
        bool tmp_is_dir = false;

        if (method == LOAD_PEM_STRING) {
            /* Concatenate PEMs and load via the PEM-string API. */
            BIO *bio = BIO_new(BIO_s_mem());
            EXPECT_NOT_NULL(bio);
            for (uint32_t i = 0; i < anchor_count; i++) {
                EXPECT_EQUAL(PEM_write_bio_X509(bio, certs[i]), 1);
            }
            char *pem_data = NULL;
            long pem_len = BIO_get_mem_data(bio, &pem_data);
            EXPECT_TRUE(pem_len > 0);
            char *pem_str = malloc(pem_len + 1);
            EXPECT_NOT_NULL(pem_str);
            memcpy(pem_str, pem_data, pem_len);
            pem_str[pem_len] = '\0';
            EXPECT_SUCCESS(s2n_x509_trust_store_add_pem(&trust_store, pem_str));
            free(pem_str);
            BIO_free(bio);
        } else if (method == LOAD_CA_FILE) {
    #ifdef _WIN32
            /* mkstemp and mkdtemp are not available on Windows */
            continue;
    #endif
            /* Write all PEMs into one file and load via the CA-file API. */
            int fd = mkstemp(tmp_path);
            EXPECT_TRUE(fd >= 0);
            FILE *fp = fdopen(fd, "w");
            EXPECT_NOT_NULL(fp);
            for (uint32_t i = 0; i < anchor_count; i++) {
                EXPECT_EQUAL(PEM_write_X509(fp, certs[i]), 1);
            }
            fclose(fp);
            EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, tmp_path, NULL));
        } else {
    #ifdef _WIN32
            /* mkdtemp is not available on Windows */
            continue;
    #endif
            /* Write each PEM into a hashed file inside a temp dir and load via
             * the CA-directory (CApath) API. */
            EXPECT_NOT_NULL(mkdtemp(tmp_path));
            tmp_is_dir = true;
            for (uint32_t i = 0; i < anchor_count; i++) {
                uint32_t hash = X509_NAME_hash(X509_get_subject_name(certs[i]));
                /* Multiple certs may share a hash bucket; disambiguate with .N. */
                snprintf(dir_files[i], sizeof(dir_files[i]), "%s/%08x.%u", tmp_path, hash, i);
                FILE *fp = fopen(dir_files[i], "w");
                EXPECT_NOT_NULL(fp);
                EXPECT_EQUAL(PEM_write_X509(fp, certs[i]), 1);
                fclose(fp);
            }
            EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, NULL, tmp_path));
            /* CA directories use lazy loading (hash-dir lookup): certs only
             * appear in X509_STORE_get0_objects after an explicit lookup. In
             * production, the libcrypto verification path triggers these
             * lookups during X509_verify_cert. Force-add the certs here so the
             * snapshot build (which enumerates get0_objects) can see them. */
            for (uint32_t i = 0; i < anchor_count; i++) {
                X509_STORE_add_cert(trust_store.trust_store, certs[i]);
            }
        }

        /* Collect the store's authoritative DER multiset (via i2d_X509). */
        struct s2n_blob expected[MAX_ANCHORS_PER_SET] = { 0 };
        uint32_t expected_count = 0;
        EXPECT_OK(s2n_test_store_ders(trust_store.trust_store, expected,
                MAX_ANCHORS_PER_SET, &expected_count));

        /* Build/acquire the snapshot and assert the multiset round-trip. */
        struct s2n_trust_anchor_snapshot *snapshot = NULL;
        EXPECT_OK(s2n_x509_trust_store_snapshot_acquire(&trust_store, &snapshot));
        EXPECT_NOT_NULL(snapshot);

        EXPECT_OK(s2n_test_assert_multiset_equal(snapshot->anchors, snapshot->count,
                expected, expected_count));

        /* Every anchor's parsed span view must borrow from its own DER. */
        for (uint32_t i = 0; i < snapshot->count; i++) {
            EXPECT_EQUAL(snapshot->anchors[i].parsed.raw.data, snapshot->anchors[i].der.data);
            EXPECT_EQUAL(snapshot->anchors[i].parsed.raw.size, snapshot->anchors[i].der.size);
        }

        EXPECT_OK(s2n_x509_trust_store_snapshot_release(&trust_store, snapshot));

        /* Cleanup. */
        for (uint32_t i = 0; i < expected_count; i++) {
            EXPECT_SUCCESS(s2n_free(&expected[i]));
        }
        s2n_x509_trust_store_wipe(&trust_store);
        for (uint32_t i = 0; i < anchor_count; i++) {
            X509_free(certs[i]);
            EVP_PKEY_free(keys[i]);
        }

        /* Remove temp file/dir. */
        if (method == LOAD_CA_FILE) {
            unlink(tmp_path);
        } else if (tmp_is_dir) {
            for (uint32_t i = 0; i < anchor_count; i++) {
                unlink(dir_files[i]);
            }
            rmdir(tmp_path);
        }
    }

    /* Snapshot-mutation consistency (): an in-flight validation
     * holding a snapshot reference keeps its consistent view even when the store
     * is mutated; the next acquire sees the rebuilt snapshot. */
    {
        struct s2n_x509_trust_store store = { 0 };
        s2n_x509_trust_store_init_empty(&store);

        X509 *certs_a[MAX_ANCHORS_PER_SET] = { 0 };
        EVP_PKEY *keys_a[MAX_ANCHORS_PER_SET] = { 0 };
        EXPECT_OK(s2n_test_populate_store(&store, 3, 0xA000, certs_a, keys_a));

        /* Simulate an in-flight validation: acquire and hold. */
        struct s2n_trust_anchor_snapshot *in_flight = NULL;
        EXPECT_OK(s2n_x509_trust_store_snapshot_acquire(&store, &in_flight));
        EXPECT_NOT_NULL(in_flight);
        EXPECT_EQUAL(in_flight->count, 3);

        /* A second acquire before mutation returns the same cached object. */
        struct s2n_trust_anchor_snapshot *same = NULL;
        EXPECT_OK(s2n_x509_trust_store_snapshot_acquire(&store, &same));
        EXPECT_EQUAL(same, in_flight);
        EXPECT_OK(s2n_x509_trust_store_snapshot_release(&store, same));

        /* Capture the in-flight snapshot's DER so we can prove it is unchanged
         * after the mutation below. */
        uint32_t held_count = in_flight->count;
        struct s2n_blob held_der[MAX_ANCHORS_PER_SET] = { 0 };
        for (uint32_t i = 0; i < held_count; i++) {
            EXPECT_SUCCESS(s2n_alloc(&held_der[i], in_flight->anchors[i].der.size));
            EXPECT_MEMCPY_SUCCESS(held_der[i].data, in_flight->anchors[i].der.data,
                    in_flight->anchors[i].der.size);
        }

        /* Mutate the store: add two more CAs. This must invalidate the cached
         * pointer but leave the in-flight snapshot untouched. */
        X509 *certs_b[MAX_ANCHORS_PER_SET] = { 0 };
        EVP_PKEY *keys_b[MAX_ANCHORS_PER_SET] = { 0 };
        EXPECT_OK(s2n_test_populate_store(&store, 2, 0xB000, certs_b, keys_b));

        /* The in-flight snapshot is unchanged (immutable, consistent view). */
        EXPECT_EQUAL(in_flight->count, held_count);
        for (uint32_t i = 0; i < held_count; i++) {
            EXPECT_EQUAL(in_flight->anchors[i].der.size, held_der[i].size);
            EXPECT_BYTEARRAY_EQUAL(in_flight->anchors[i].der.data, held_der[i].data,
                    held_der[i].size);
        }

        /* A new acquire rebuilds and sees all 5 certs; it is a different object. */
        struct s2n_trust_anchor_snapshot *rebuilt = NULL;
        EXPECT_OK(s2n_x509_trust_store_snapshot_acquire(&store, &rebuilt));
        EXPECT_NOT_NULL(rebuilt);
        EXPECT_NOT_EQUAL(rebuilt, in_flight);
        EXPECT_EQUAL(rebuilt->count, 5);
        EXPECT_OK(s2n_x509_trust_store_snapshot_release(&store, rebuilt));

        /* Release the in-flight reference last. */
        EXPECT_OK(s2n_x509_trust_store_snapshot_release(&store, in_flight));

        for (uint32_t i = 0; i < held_count; i++) {
            EXPECT_SUCCESS(s2n_free(&held_der[i]));
        }
        s2n_x509_trust_store_wipe(&store);
        for (uint32_t i = 0; i < 3; i++) {
            X509_free(certs_a[i]);
            EVP_PKEY_free(keys_a[i]);
        }
        for (uint32_t i = 0; i < 2; i++) {
            X509_free(certs_b[i]);
            EVP_PKEY_free(keys_b[i]);
        }
    }

    /* TSan concurrency (): many threads concurrently acquire,
     * read, and release the shared snapshot with no data races. Run under
     * ThreadSanitizer to detect races on the refcount and the immutable data. */
    {
        struct s2n_x509_trust_store store = { 0 };
        s2n_x509_trust_store_init_empty(&store);

        X509 *certs[MAX_ANCHORS_PER_SET] = { 0 };
        EVP_PKEY *keys[MAX_ANCHORS_PER_SET] = { 0 };
        EXPECT_OK(s2n_test_populate_store(&store, MAX_ANCHORS_PER_SET, 0xC000, certs, keys));

        /* Pre-build the snapshot so all readers share one immutable object. */
        struct s2n_trust_anchor_snapshot *primed = NULL;
        EXPECT_OK(s2n_x509_trust_store_snapshot_acquire(&store, &primed));
        EXPECT_OK(s2n_x509_trust_store_snapshot_release(&store, primed));

        pthread_t readers[S2N_TEST_NUM_READERS] = { 0 };
        struct s2n_test_reader_args args[S2N_TEST_NUM_READERS] = { 0 };
        for (int t = 0; t < S2N_TEST_NUM_READERS; t++) {
            args[t].store = &store;
            args[t].iterations = 200;
            EXPECT_EQUAL(pthread_create(&readers[t], NULL, s2n_test_snapshot_reader, &args[t]), 0);
        }
        for (int t = 0; t < S2N_TEST_NUM_READERS; t++) {
            void *ret = NULL;
            EXPECT_EQUAL(pthread_join(readers[t], &ret), 0);
            /* Non-NULL return means the thread completed all iterations
             * without an acquire/release error. */
            EXPECT_EQUAL(ret, &args[t]);
            EXPECT_EQUAL(args[t].observed_count, MAX_ANCHORS_PER_SET);
        }

        s2n_x509_trust_store_wipe(&store);
        for (uint32_t i = 0; i < MAX_ANCHORS_PER_SET; i++) {
            X509_free(certs[i]);
            EVP_PKEY_free(keys[i]);
        }
    }

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
