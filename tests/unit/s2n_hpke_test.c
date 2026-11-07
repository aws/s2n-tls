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

#include "crypto/s2n_hpke.h"

#include "crypto/s2n_libcrypto.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define S2N_HPKE_TEST_ENCRYPTIONS 6

/* Base mode vectors for the suites that ECH uses, from RFC 9180 Appendix A
 * where it has one.
 * Every vector encrypts the same plaintext, with the AAD "Count-<sequence number>". */
struct s2n_hpke_test_vector {
    uint16_t aead_id;
    const char *info;
    const char *sk_e;
    const char *pk_r;
    const char *sk_r;
    const char *enc;
    struct {
        uint16_t sequence_number;
        const char *ct;
    } encryptions[S2N_HPKE_TEST_ENCRYPTIONS];
};

static const char *s2n_hpke_test_pt = "4265617574792069732074727574682c20747275746820626561757479";

static const struct s2n_hpke_test_vector s2n_hpke_test_vectors[] = {
    /**
     *= https://www.rfc-editor.org/rfc/rfc9180#appendix-A.1.1
     *= type=test
     *#    mode: 0
     *#    kem_id: 32
     *#    kdf_id: 1
     *#    aead_id: 1
     *#    info: 4f6465206f6e2061204772656369616e2055726e
     *
     *= https://www.rfc-editor.org/rfc/rfc9180#appendix-A.1.1
     *= type=test
     *#    pkRm:
     *#    3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d
     *#    skRm:
     *#    4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8
     *#    enc:
     *#    37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431
     *
     *= https://www.rfc-editor.org/rfc/rfc9180#appendix-A.1.1.1
     *= type=test
     *#    sequence number: 0
     *#    pt: 4265617574792069732074727574682c20747275746820626561757479
     *#    aad: 436f756e742d30
     *#    nonce: 56d890e5accaaf011cff4b7d
     *#    ct: f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9
     *#    6d8770ac83d07bea87e13c512a
     */
    {
            .aead_id = S2N_HPKE_AEAD_AES_128_GCM,
            .info = "4f6465206f6e2061204772656369616e2055726e",
            .sk_e = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
            .pk_r = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
            .sk_r = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
            .enc = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
            .encryptions = {
                    { 0, "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9"
                         "6d8770ac83d07bea87e13c512a" },
                    { 1, "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab25"
                         "1c03d0c22a56b8ca42c2063b84" },
                    { 2, "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb7251649158"
                         "8d96a19ad4a683518973dcc180" },
                    { 4, "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a"
                         "09fc0012bc69fccaa251c0246d" },
                    { 255, "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505b"
                           "f106deefec4a49ac38d71c9e0a" },
                    { 256, "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3"
                           "fbeda97d2e0e1aba483a2df9f2" },
            },
    },
    /**
     *= https://www.rfc-editor.org/rfc/rfc9180#appendix-A.2.1
     *= type=test
     *#    mode: 0
     *#    kem_id: 32
     *#    kdf_id: 1
     *#    aead_id: 3
     *#    info: 4f6465206f6e2061204772656369616e2055726e
     *
     *= https://www.rfc-editor.org/rfc/rfc9180#appendix-A.2.1
     *= type=test
     *#    pkRm:
     *#    4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a
     *#    skRm:
     *#    8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb
     *#    enc:
     *#    1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a
     *
     *= https://www.rfc-editor.org/rfc/rfc9180#appendix-A.2.1.1
     *= type=test
     *#    sequence number: 0
     *#    pt: 4265617574792069732074727574682c20747275746820626561757479
     *#    aad: 436f756e742d30
     *#    nonce: 5c4d98150661b848853b547f
     *#    ct: 1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db
     *#    21993c62ce81883d2dd1b51a28
     */
    {
            .aead_id = S2N_HPKE_AEAD_CHACHA20_POLY1305,
            .info = "4f6465206f6e2061204772656369616e2055726e",
            .sk_e = "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
            .pk_r = "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
            .sk_r = "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
            .enc = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
            .encryptions = {
                    { 0, "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db"
                         "21993c62ce81883d2dd1b51a28" },
                    { 1, "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e"
                         "85285337cc95ba5f59992dc98c" },
                    { 2, "71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02"
                         "b4f10ecac6f48c32f878fae86b" },
                    { 4, "63357a2aa291f5a4e5f27db6baa2af8cf77427c7c1a909e0b37214dd47db122b"
                         "b153495ff0b02e9e54a50dbe16" },
                    { 255, "18ab939d63ddec9f6ac2b60d61d36a7375d2070c9b683861110757062c52b888"
                           "0a5f6b3936da9cd6c23ef2a95c" },
                    { 256, "7a4a13e9ef23978e2c520fd4d2e757514ae160cd0cd05e556ef692370ca53076"
                           "214c0c40d4c728d6ed9e727a5b" },
            },
    },
    /* RFC 9180 Appendix A has no AES-256-GCM vector for DHKEM(X25519, HKDF-SHA256).
     * This one is the mode 0, kem_id 32, kdf_id 1, aead_id 2 entry of the CFRG HPKE
     * test vectors, which AWS-LC also ships:
     * https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json
     */
    {
            .aead_id = S2N_HPKE_AEAD_AES_256_GCM,
            .info = "4f6465206f6e2061204772656369616e2055726e",
            .sk_e = "179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11",
            .pk_r = "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c",
            .sk_r = "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d",
            .enc = "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256",
            .encryptions = {
                    { 0, "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be99319"
                         "80a41de125a925cdad859d5b7a" },
                    { 1, "2c43aff25343fdbff864506f0818b9d87df84ea01b1a2144d23b4d40c26bf655"
                         "fdf197fe40297a8aebeed5cc2d" },
                    { 2, "e0a8f2cf92ff61215edbb8c55dc31fe9e2eb42a5685867bb6854211542099f9e"
                         "940c4b41c192bc390835b1a5f7" },
                    { 4, "448a8892f261cbb6bf5b7b64a4fae8a2c86492494b069c10525895d871c27c2f"
                         "12cd17e0588fedaba9f7b0cd4c" },
                    { 255, "f6ad1823eb0b932d04b6e23010eea64f1fe5edd0583dae5ba27ca6363f4ea104"
                           "bd217331460ef4208040423641" },
                    { 256, "53624f4f9f173453b14e633b45390ff54cacaa4428d44baee1bff8133fab1ab3"
                           "afe60f88e4634b525c54e92eda" },
            },
    },
};

/* Writes the AAD that every RFC 9180 Appendix A vector uses: "Count-<sequence number>" */
static S2N_RESULT s2n_hpke_test_aad(uint16_t sequence_number, uint8_t *buffer, size_t buffer_size, struct s2n_blob *aad)
{
    int written = snprintf((char *) buffer, buffer_size, "Count-%u", sequence_number);
    RESULT_ENSURE_GT(written, 0);
    RESULT_ENSURE_LT((size_t) written, buffer_size);
    RESULT_GUARD_POSIX(s2n_blob_init(aad, buffer, written));
    return S2N_RESULT_OK;
}

struct s2n_hpke_test_pair {
    struct s2n_hpke_key *recipient_key;
    struct s2n_hpke_ctx *sender;
    struct s2n_hpke_ctx *recipient;
    uint8_t enc_bytes[S2N_HPKE_X25519_ENC_LEN];
    struct s2n_blob enc;
};

static S2N_CLEANUP_RESULT s2n_hpke_test_pair_free(struct s2n_hpke_test_pair *pair)
{
    RESULT_ENSURE_REF(pair);
    RESULT_GUARD(s2n_hpke_key_free(&pair->recipient_key));
    RESULT_GUARD(s2n_hpke_ctx_free(&pair->sender));
    RESULT_GUARD(s2n_hpke_ctx_free(&pair->recipient));
    return S2N_RESULT_OK;
}

/* Generates a recipient key and sets up a sender for it. The recipient is created but not set up. */
static S2N_RESULT s2n_hpke_test_pair_init(struct s2n_hpke_test_pair *pair, uint16_t aead_id,
        const struct s2n_blob *info)
{
    RESULT_ENSURE_REF(pair);
    RESULT_GUARD(s2n_hpke_key_new(&pair->recipient_key));
    RESULT_GUARD(s2n_hpke_key_generate(pair->recipient_key, S2N_HPKE_KEM_X25519_HKDF_SHA256));

    uint8_t public_key_bytes[S2N_HPKE_X25519_PUBLIC_KEY_LEN] = { 0 };
    struct s2n_blob public_key = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&public_key, public_key_bytes, sizeof(public_key_bytes)));
    RESULT_GUARD(s2n_hpke_key_public_key(pair->recipient_key, &public_key));

    RESULT_GUARD(s2n_hpke_ctx_new(&pair->sender));
    RESULT_GUARD_POSIX(s2n_blob_init(&pair->enc, pair->enc_bytes, sizeof(pair->enc_bytes)));
    RESULT_GUARD(s2n_hpke_setup_sender(pair->sender, S2N_HPKE_KEM_X25519_HKDF_SHA256,
            S2N_HPKE_KDF_HKDF_SHA256, aead_id, &public_key, info, &pair->enc));

    RESULT_GUARD(s2n_hpke_ctx_new(&pair->recipient));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Every AWS-LC and AWS-LC-FIPS release that s2n-tls supports provides EVP_HPKE_*.
     * HPKE is AWS-LC only: see crypto/s2n_hpke.h for why BoringSSL is excluded. */
    EXPECT_EQUAL(s2n_hpke_is_supported(), s2n_libcrypto_is_awslc());

    /* Only the suites that ECH uses are supported */
    {
        const uint16_t aeads[] = {
            S2N_HPKE_AEAD_AES_128_GCM,
            S2N_HPKE_AEAD_AES_256_GCM,
            S2N_HPKE_AEAD_CHACHA20_POLY1305,
        };
        for (size_t i = 0; i < s2n_array_len(aeads); i++) {
            EXPECT_EQUAL(s2n_hpke_suite_is_supported(S2N_HPKE_KEM_X25519_HKDF_SHA256,
                                 S2N_HPKE_KDF_HKDF_SHA256, aeads[i]),
                    s2n_hpke_is_supported());
        }

        /* RFC 9180 7.1: DHKEM(P-256, HKDF-SHA256) and DHKEM(X448, HKDF-SHA512).
         * 0x0041 is ML-KEM-768 from the IANA HPKE registry, which AWS-LC may offer. */
        const uint16_t unsupported_kems[] = { 0x0000, 0x0010, 0x0021, 0x0041, 0xFFFF };
        for (size_t i = 0; i < s2n_array_len(unsupported_kems); i++) {
            EXPECT_FALSE(s2n_hpke_suite_is_supported(unsupported_kems[i],
                    S2N_HPKE_KDF_HKDF_SHA256, S2N_HPKE_AEAD_AES_128_GCM));
        }

        /* RFC 9180 7.2: HKDF-SHA384, which AWS-LC may offer, and HKDF-SHA512 */
        const uint16_t unsupported_kdfs[] = { 0x0000, 0x0002, 0x0003, 0xFFFF };
        for (size_t i = 0; i < s2n_array_len(unsupported_kdfs); i++) {
            EXPECT_FALSE(s2n_hpke_suite_is_supported(S2N_HPKE_KEM_X25519_HKDF_SHA256,
                    unsupported_kdfs[i], S2N_HPKE_AEAD_AES_128_GCM));
        }

        /* RFC 9180 7.3: 0xFFFF is the export-only AEAD */
        const uint16_t unsupported_aeads[] = { 0x0000, 0x0004, 0xFFFF };
        for (size_t i = 0; i < s2n_array_len(unsupported_aeads); i++) {
            EXPECT_FALSE(s2n_hpke_suite_is_supported(S2N_HPKE_KEM_X25519_HKDF_SHA256,
                    S2N_HPKE_KDF_HKDF_SHA256, unsupported_aeads[i]));
        }
    };

    /* Without HPKE every operation fails, and freeing NULL still succeeds */
    if (!s2n_hpke_is_supported()) {
        struct s2n_hpke_key *key = NULL;
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_key_new(&key), S2N_ERR_UNIMPLEMENTED);
        EXPECT_NULL(key);
        EXPECT_OK(s2n_hpke_key_free(&key));
        struct s2n_hpke_ctx *ctx = NULL;
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_ctx_new(&ctx), S2N_ERR_UNIMPLEMENTED);
        EXPECT_NULL(ctx);
        EXPECT_OK(s2n_hpke_ctx_free(&ctx));

        uint8_t bytes[S2N_HPKE_X25519_PUBLIC_KEY_LEN] = { 0 };
        struct s2n_blob blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&blob, bytes, sizeof(bytes)));
        DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
        uint16_t overhead = 0;

        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_key_generate(key, S2N_HPKE_KEM_X25519_HKDF_SHA256),
                S2N_ERR_UNIMPLEMENTED);
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_key_init(key, S2N_HPKE_KEM_X25519_HKDF_SHA256, &blob),
                S2N_ERR_UNIMPLEMENTED);
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_key_public_key(key, &blob), S2N_ERR_UNIMPLEMENTED);
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_setup_recipient(ctx, key, S2N_HPKE_KDF_HKDF_SHA256,
                                        S2N_HPKE_AEAD_AES_128_GCM, &blob, &blob),
                S2N_ERR_UNIMPLEMENTED);
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_setup_sender(ctx, S2N_HPKE_KEM_X25519_HKDF_SHA256,
                                        S2N_HPKE_KDF_HKDF_SHA256, S2N_HPKE_AEAD_AES_128_GCM, &blob, &blob, &blob),
                S2N_ERR_UNIMPLEMENTED);
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_setup_sender_with_seed(ctx, S2N_HPKE_KEM_X25519_HKDF_SHA256,
                                        S2N_HPKE_KDF_HKDF_SHA256, S2N_HPKE_AEAD_AES_128_GCM, &blob, &blob, &blob, &blob),
                S2N_ERR_UNIMPLEMENTED);
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_seal(ctx, &blob, &blob, &out), S2N_ERR_UNIMPLEMENTED);
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_open(ctx, &blob, &blob, &out), S2N_ERR_UNIMPLEMENTED);
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_max_overhead(ctx, &overhead), S2N_ERR_UNIMPLEMENTED);
        EXPECT_EQUAL(s2n_stuffer_data_available(&out), 0);

        END_TEST();
    }

    /* Base mode vectors */
    for (size_t i = 0; i < s2n_array_len(s2n_hpke_test_vectors); i++) {
        const struct s2n_hpke_test_vector *vector = &s2n_hpke_test_vectors[i];
        S2N_BLOB_FROM_HEX(info, vector->info);
        S2N_BLOB_FROM_HEX(sk_e, vector->sk_e);
        S2N_BLOB_FROM_HEX(pk_r, vector->pk_r);
        S2N_BLOB_FROM_HEX(sk_r, vector->sk_r);
        S2N_BLOB_FROM_HEX(expected_enc, vector->enc);
        S2N_BLOB_FROM_HEX(pt, s2n_hpke_test_pt);

        DEFER_CLEANUP(struct s2n_hpke_key *recipient_key = NULL, s2n_hpke_key_free);
        EXPECT_OK(s2n_hpke_key_new(&recipient_key));
        EXPECT_OK(s2n_hpke_key_init(recipient_key, S2N_HPKE_KEM_X25519_HKDF_SHA256, &sk_r));

        uint8_t public_key_bytes[S2N_HPKE_X25519_PUBLIC_KEY_LEN] = { 0 };
        struct s2n_blob public_key = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&public_key, public_key_bytes, sizeof(public_key_bytes)));
        EXPECT_OK(s2n_hpke_key_public_key(recipient_key, &public_key));
        S2N_BLOB_EXPECT_EQUAL(public_key, pk_r);

        DEFER_CLEANUP(struct s2n_hpke_ctx *sender = NULL, s2n_hpke_ctx_free);
        EXPECT_OK(s2n_hpke_ctx_new(&sender));
        uint8_t enc_bytes[S2N_HPKE_X25519_ENC_LEN] = { 0 };
        struct s2n_blob enc = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&enc, enc_bytes, sizeof(enc_bytes)));
        EXPECT_OK(s2n_hpke_setup_sender_with_seed(sender, S2N_HPKE_KEM_X25519_HKDF_SHA256,
                S2N_HPKE_KDF_HKDF_SHA256, vector->aead_id, &pk_r, &info, &sk_e, &enc));
        S2N_BLOB_EXPECT_EQUAL(enc, expected_enc);

        DEFER_CLEANUP(struct s2n_hpke_ctx *recipient = NULL, s2n_hpke_ctx_free);
        EXPECT_OK(s2n_hpke_ctx_new(&recipient));
        EXPECT_OK(s2n_hpke_setup_recipient(recipient, recipient_key,
                S2N_HPKE_KDF_HKDF_SHA256, vector->aead_id, &expected_enc, &info));

        /* The sequence number advances with every seal and open,
         * so encrypt every message up to the last one the RFC lists. */
        size_t next_encryption = 0;
        uint16_t last_sequence_number = vector->encryptions[S2N_HPKE_TEST_ENCRYPTIONS - 1].sequence_number;
        for (uint16_t sequence_number = 0; sequence_number <= last_sequence_number; sequence_number++) {
            uint8_t aad_bytes[16] = { 0 };
            struct s2n_blob aad = { 0 };
            EXPECT_OK(s2n_hpke_test_aad(sequence_number, aad_bytes, sizeof(aad_bytes), &aad));

            DEFER_CLEANUP(struct s2n_stuffer ct = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ct, 0));
            EXPECT_OK(s2n_hpke_seal(sender, &aad, &pt, &ct));

            DEFER_CLEANUP(struct s2n_stuffer opened = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&opened, 0));
            struct s2n_blob ct_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ct_blob, ct.blob.data, s2n_stuffer_data_available(&ct)));
            EXPECT_OK(s2n_hpke_open(recipient, &aad, &ct_blob, &opened));
            EXPECT_EQUAL(s2n_stuffer_data_available(&opened), pt.size);
            EXPECT_BYTEARRAY_EQUAL(opened.blob.data, pt.data, pt.size);

            if (sequence_number != vector->encryptions[next_encryption].sequence_number) {
                continue;
            }
            S2N_BLOB_FROM_HEX(expected_ct, vector->encryptions[next_encryption].ct);
            S2N_BLOB_EXPECT_EQUAL(ct_blob, expected_ct);
            next_encryption++;
        }
        EXPECT_EQUAL(next_encryption, S2N_HPKE_TEST_ENCRYPTIONS);
    }

    const uint16_t ech_aeads[] = {
        S2N_HPKE_AEAD_AES_128_GCM,
        S2N_HPKE_AEAD_AES_256_GCM,
        S2N_HPKE_AEAD_CHACHA20_POLY1305,
    };
    uint8_t info_bytes[] = "tls ech";
    struct s2n_blob info = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&info, info_bytes, sizeof(info_bytes) - 1));
    uint8_t aad_bytes[] = "client hello outer";
    struct s2n_blob aad = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&aad, aad_bytes, sizeof(aad_bytes) - 1));
    uint8_t pt_bytes[] = "client hello inner";
    struct s2n_blob pt = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&pt, pt_bytes, sizeof(pt_bytes) - 1));

    for (size_t i = 0; i < s2n_array_len(ech_aeads); i++) {
        /* Seal and open round trip with a generated key */
        {
            DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
            EXPECT_OK(s2n_hpke_test_pair_init(&pair, ech_aeads[i], &info));
            EXPECT_EQUAL(pair.enc.size, S2N_HPKE_X25519_ENC_LEN);
            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &pair.enc, &info));

            /* Each AEAD adds a 16-byte tag */
            uint16_t overhead = 0;
            EXPECT_OK(s2n_hpke_max_overhead(pair.sender, &overhead));
            EXPECT_EQUAL(overhead, 16);
            EXPECT_OK(s2n_hpke_max_overhead(pair.recipient, &overhead));
            EXPECT_EQUAL(overhead, 16);

            /* Several messages, so that the sequence numbers must stay in step */
            for (size_t message = 0; message < 3; message++) {
                DEFER_CLEANUP(struct s2n_stuffer ct = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ct, 0));
                EXPECT_OK(s2n_hpke_seal(pair.sender, &aad, &pt, &ct));
                EXPECT_EQUAL(s2n_stuffer_data_available(&ct), pt.size + overhead);

                struct s2n_blob ct_blob = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&ct_blob, ct.blob.data, s2n_stuffer_data_available(&ct)));
                DEFER_CLEANUP(struct s2n_stuffer opened = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&opened, 0));
                EXPECT_OK(s2n_hpke_open(pair.recipient, &aad, &ct_blob, &opened));
                EXPECT_EQUAL(s2n_stuffer_data_available(&opened), pt.size);
                EXPECT_BYTEARRAY_EQUAL(opened.blob.data, pt.data, pt.size);
            }
        };

        /* Open fails if the AAD does not match */
        {
            DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
            EXPECT_OK(s2n_hpke_test_pair_init(&pair, ech_aeads[i], &info));
            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &pair.enc, &info));

            DEFER_CLEANUP(struct s2n_stuffer ct = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ct, 0));
            EXPECT_OK(s2n_hpke_seal(pair.sender, &aad, &pt, &ct));
            struct s2n_blob ct_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ct_blob, ct.blob.data, s2n_stuffer_data_available(&ct)));

            uint8_t wrong_aad_bytes[sizeof(aad_bytes)] = { 0 };
            EXPECT_MEMCPY_SUCCESS(wrong_aad_bytes, aad.data, aad.size);
            wrong_aad_bytes[0] ^= 1;
            struct s2n_blob wrong_aad = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&wrong_aad, wrong_aad_bytes, aad.size));

            DEFER_CLEANUP(struct s2n_stuffer opened = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&opened, 0));
            EXPECT_ERROR_WITH_ERRNO(s2n_hpke_open(pair.recipient, &wrong_aad, &ct_blob, &opened),
                    S2N_ERR_DECRYPT);
            EXPECT_EQUAL(s2n_stuffer_data_available(&opened), 0);

            /* A failed open does not advance the sequence number */
            EXPECT_OK(s2n_hpke_open(pair.recipient, &aad, &ct_blob, &opened));
            EXPECT_EQUAL(s2n_stuffer_data_available(&opened), pt.size);
            EXPECT_BYTEARRAY_EQUAL(opened.blob.data, pt.data, pt.size);
        };

        /* Open fails if the ciphertext is truncated */
        {
            DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
            EXPECT_OK(s2n_hpke_test_pair_init(&pair, ech_aeads[i], &info));
            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &pair.enc, &info));

            DEFER_CLEANUP(struct s2n_stuffer ct = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ct, 0));
            EXPECT_OK(s2n_hpke_seal(pair.sender, &aad, &pt, &ct));
            uint32_t ct_len = s2n_stuffer_data_available(&ct);

            /* One byte short, shorter than the tag, and empty */
            const uint32_t truncated_lens[] = { ct_len - 1, 15, 0 };
            for (size_t j = 0; j < s2n_array_len(truncated_lens); j++) {
                struct s2n_blob truncated = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&truncated, ct.blob.data, truncated_lens[j]));
                DEFER_CLEANUP(struct s2n_stuffer opened = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&opened, 0));
                EXPECT_ERROR_WITH_ERRNO(s2n_hpke_open(pair.recipient, &aad, &truncated, &opened),
                        S2N_ERR_DECRYPT);
                EXPECT_EQUAL(s2n_stuffer_data_available(&opened), 0);
            }
        };

        /* Recipient setup fails if enc is not the X25519 length */
        {
            DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
            EXPECT_OK(s2n_hpke_test_pair_init(&pair, ech_aeads[i], &info));

            /* Start from a context that was set up, so that a failed setup must discard it */
            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &pair.enc, &info));

            uint8_t long_enc_bytes[S2N_HPKE_X25519_ENC_LEN + 1] = { 0 };
            EXPECT_MEMCPY_SUCCESS(long_enc_bytes, pair.enc.data, pair.enc.size);
            const uint32_t wrong_lens[] = { 0, S2N_HPKE_X25519_ENC_LEN - 1, S2N_HPKE_X25519_ENC_LEN + 1 };
            for (size_t j = 0; j < s2n_array_len(wrong_lens); j++) {
                struct s2n_blob wrong_enc = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&wrong_enc, long_enc_bytes, wrong_lens[j]));
                EXPECT_ERROR_WITH_ERRNO(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                                                S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &wrong_enc, &info),
                        S2N_ERR_DECRYPT);

                /* The failed setup leaves the context unusable */
                struct s2n_blob ct = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&ct, long_enc_bytes, sizeof(long_enc_bytes)));
                DEFER_CLEANUP(struct s2n_stuffer opened = { 0 }, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&opened, 0));
                EXPECT_ERROR_WITH_ERRNO(s2n_hpke_open(pair.recipient, &aad, &ct, &opened),
                        S2N_ERR_INVALID_STATE);
            }

            /* The same context can then be set up with the correct enc */
            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &pair.enc, &info));
            DEFER_CLEANUP(struct s2n_stuffer ct = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ct, 0));
            EXPECT_OK(s2n_hpke_seal(pair.sender, &aad, &pt, &ct));
            struct s2n_blob ct_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ct_blob, ct.blob.data, s2n_stuffer_data_available(&ct)));
            DEFER_CLEANUP(struct s2n_stuffer opened = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&opened, 0));
            EXPECT_OK(s2n_hpke_open(pair.recipient, &aad, &ct_blob, &opened));
        };

        /**
         * Recipient setup fails if enc is a small-order X25519 point
         *
         *= https://www.rfc-editor.org/rfc/rfc9180#section-7.1.4
         *= type=test
         *# In particular, recipients MUST
         *# check whether the Diffie-Hellman shared secret is the all-zero value
         *# and abort if so.
         */
        {
            DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
            EXPECT_OK(s2n_hpke_test_pair_init(&pair, ech_aeads[i], &info));
            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &pair.enc, &info));

            /* u = 0 and u = 1 give an all-zero shared secret for every private key */
            uint8_t small_order_points[][S2N_HPKE_X25519_ENC_LEN] = { { 0 }, { 1 } };
            for (size_t j = 0; j < s2n_array_len(small_order_points); j++) {
                struct s2n_blob bad_enc = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&bad_enc, small_order_points[j], S2N_HPKE_X25519_ENC_LEN));
                EXPECT_ERROR_WITH_ERRNO(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                                                S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &bad_enc, &info),
                        S2N_ERR_DECRYPT);
                uint16_t overhead = 0;
                EXPECT_ERROR_WITH_ERRNO(s2n_hpke_max_overhead(pair.recipient, &overhead),
                        S2N_ERR_INVALID_STATE);
            }
        };

        /**
         * Sender setup fails if the recipient's public key is a small-order X25519 point
         *
         *= https://www.rfc-editor.org/rfc/rfc9180#section-7.1.4
         *= type=test
         *# For X25519 and X448, public keys and Diffie-Hellman outputs MUST be
         *# validated as described in [RFC7748].
         */
        {
            DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
            EXPECT_OK(s2n_hpke_test_pair_init(&pair, ech_aeads[i], &info));

            uint8_t zero_public_key_bytes[S2N_HPKE_X25519_PUBLIC_KEY_LEN] = { 0 };
            struct s2n_blob zero_public_key = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&zero_public_key, zero_public_key_bytes, sizeof(zero_public_key_bytes)));
            uint8_t enc_bytes[S2N_HPKE_X25519_ENC_LEN] = { 0 };
            struct s2n_blob enc = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&enc, enc_bytes, sizeof(enc_bytes)));
            EXPECT_ERROR_WITH_ERRNO(s2n_hpke_setup_sender(pair.sender, S2N_HPKE_KEM_X25519_HKDF_SHA256,
                                            S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &zero_public_key, &info, &enc),
                    S2N_ERR_ENCRYPT);

            DEFER_CLEANUP(struct s2n_stuffer ct = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ct, 0));
            EXPECT_ERROR_WITH_ERRNO(s2n_hpke_seal(pair.sender, &aad, &pt, &ct), S2N_ERR_INVALID_STATE);
        };

        /* A sender cannot open and a recipient cannot seal. Both are caller errors, not decryption failures. */
        {
            DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
            EXPECT_OK(s2n_hpke_test_pair_init(&pair, ech_aeads[i], &info));
            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &pair.enc, &info));

            DEFER_CLEANUP(struct s2n_stuffer ct = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ct, 0));
            EXPECT_ERROR_WITH_ERRNO(s2n_hpke_seal(pair.recipient, &aad, &pt, &ct), S2N_ERR_INVALID_STATE);
            EXPECT_EQUAL(s2n_stuffer_data_available(&ct), 0);

            EXPECT_OK(s2n_hpke_seal(pair.sender, &aad, &pt, &ct));
            struct s2n_blob ct_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ct_blob, ct.blob.data, s2n_stuffer_data_available(&ct)));
            DEFER_CLEANUP(struct s2n_stuffer opened = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&opened, 0));
            EXPECT_ERROR_WITH_ERRNO(s2n_hpke_open(pair.sender, &aad, &ct_blob, &opened), S2N_ERR_INVALID_STATE);
            EXPECT_EQUAL(s2n_stuffer_data_available(&opened), 0);

            /* Neither failure advanced either sequence number */
            for (size_t message = 0; message < 2; message++) {
                if (message > 0) {
                    EXPECT_SUCCESS(s2n_stuffer_wipe(&ct));
                    EXPECT_OK(s2n_hpke_seal(pair.sender, &aad, &pt, &ct));
                    EXPECT_SUCCESS(s2n_blob_init(&ct_blob, ct.blob.data, s2n_stuffer_data_available(&ct)));
                }
                EXPECT_SUCCESS(s2n_stuffer_wipe(&opened));
                EXPECT_OK(s2n_hpke_open(pair.recipient, &aad, &ct_blob, &opened));
                EXPECT_EQUAL(s2n_stuffer_data_available(&opened), pt.size);
                EXPECT_BYTEARRAY_EQUAL(opened.blob.data, pt.data, pt.size);
            }
        };

        /* Open needs room only for the plaintext, not the tag */
        {
            DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
            EXPECT_OK(s2n_hpke_test_pair_init(&pair, ech_aeads[i], &info));
            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &pair.enc, &info));

            DEFER_CLEANUP(struct s2n_stuffer ct = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ct, 0));
            EXPECT_OK(s2n_hpke_seal(pair.sender, &aad, &pt, &ct));
            struct s2n_blob ct_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ct_blob, ct.blob.data, s2n_stuffer_data_available(&ct)));

            uint8_t out_bytes[sizeof(pt_bytes) - 1] = { 0 };
            struct s2n_blob out_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&out_blob, out_bytes, sizeof(out_bytes)));
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&out, &out_blob));
            EXPECT_OK(s2n_hpke_open(pair.recipient, &aad, &ct_blob, &out));
            EXPECT_EQUAL(s2n_stuffer_data_available(&out), pt.size);
            EXPECT_BYTEARRAY_EQUAL(out.blob.data, pt.data, pt.size);
        };

        /* Seal and open append to what `out` already holds, and a failed open
         * leaves it as it was */
        {
            DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
            EXPECT_OK(s2n_hpke_test_pair_init(&pair, ech_aeads[i], &info));
            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &pair.enc, &info));
            const uint8_t prefix[] = { 0xAA, 0xBB, 0xCC };

            DEFER_CLEANUP(struct s2n_stuffer ct = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ct, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&ct, prefix, sizeof(prefix)));
            EXPECT_OK(s2n_hpke_seal(pair.sender, &aad, &pt, &ct));
            EXPECT_EQUAL(s2n_stuffer_data_available(&ct), sizeof(prefix) + pt.size + 16);
            EXPECT_BYTEARRAY_EQUAL(ct.blob.data, prefix, sizeof(prefix));
            struct s2n_blob ct_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ct_blob, ct.blob.data + sizeof(prefix),
                    s2n_stuffer_data_available(&ct) - sizeof(prefix)));

            DEFER_CLEANUP(struct s2n_stuffer opened = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&opened, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&opened, prefix, sizeof(prefix)));

            uint8_t wrong_aad_bytes[sizeof(aad_bytes)] = { 0 };
            EXPECT_MEMCPY_SUCCESS(wrong_aad_bytes, aad.data, aad.size);
            wrong_aad_bytes[0] ^= 1;
            struct s2n_blob wrong_aad = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&wrong_aad, wrong_aad_bytes, aad.size));
            EXPECT_ERROR_WITH_ERRNO(s2n_hpke_open(pair.recipient, &wrong_aad, &ct_blob, &opened), S2N_ERR_DECRYPT);
            EXPECT_EQUAL(s2n_stuffer_data_available(&opened), sizeof(prefix));
            EXPECT_BYTEARRAY_EQUAL(opened.blob.data, prefix, sizeof(prefix));

            EXPECT_OK(s2n_hpke_open(pair.recipient, &aad, &ct_blob, &opened));
            EXPECT_EQUAL(s2n_stuffer_data_available(&opened), sizeof(prefix) + pt.size);
            EXPECT_BYTEARRAY_EQUAL(opened.blob.data, prefix, sizeof(prefix));
            EXPECT_BYTEARRAY_EQUAL(opened.blob.data + sizeof(prefix), pt.data, pt.size);
        };

        /* Trial decryption, as the ECH server does it: setup with the wrong key, the wrong
         * enc, or the wrong AEAD succeeds and only open fails. The same context then sets up
         * with the right inputs and opens the first message. */
        {
            DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
            EXPECT_OK(s2n_hpke_test_pair_init(&pair, ech_aeads[i], &info));
            DEFER_CLEANUP(struct s2n_hpke_key *other_key = NULL, s2n_hpke_key_free);
            EXPECT_OK(s2n_hpke_key_new(&other_key));
            EXPECT_OK(s2n_hpke_key_generate(other_key, S2N_HPKE_KEM_X25519_HKDF_SHA256));
            /* A valid X25519 point that is not the sender's enc */
            uint8_t other_enc_bytes[S2N_HPKE_X25519_PUBLIC_KEY_LEN] = { 0 };
            struct s2n_blob other_enc = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&other_enc, other_enc_bytes, sizeof(other_enc_bytes)));
            EXPECT_OK(s2n_hpke_key_public_key(other_key, &other_enc));
            const uint16_t other_aead = ech_aeads[(i + 1) % s2n_array_len(ech_aeads)];

            DEFER_CLEANUP(struct s2n_stuffer ct = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ct, 0));
            EXPECT_OK(s2n_hpke_seal(pair.sender, &aad, &pt, &ct));
            struct s2n_blob ct_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&ct_blob, ct.blob.data, s2n_stuffer_data_available(&ct)));
            DEFER_CLEANUP(struct s2n_stuffer opened = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&opened, 0));

            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, other_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &pair.enc, &info));
            EXPECT_ERROR_WITH_ERRNO(s2n_hpke_open(pair.recipient, &aad, &ct_blob, &opened), S2N_ERR_DECRYPT);

            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &other_enc, &info));
            EXPECT_ERROR_WITH_ERRNO(s2n_hpke_open(pair.recipient, &aad, &ct_blob, &opened), S2N_ERR_DECRYPT);

            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, other_aead, &pair.enc, &info));
            EXPECT_ERROR_WITH_ERRNO(s2n_hpke_open(pair.recipient, &aad, &ct_blob, &opened), S2N_ERR_DECRYPT);
            EXPECT_EQUAL(s2n_stuffer_data_available(&opened), 0);

            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &pair.enc, &info));
            EXPECT_OK(s2n_hpke_open(pair.recipient, &aad, &ct_blob, &opened));
            EXPECT_EQUAL(s2n_stuffer_data_available(&opened), pt.size);
            EXPECT_BYTEARRAY_EQUAL(opened.blob.data, pt.data, pt.size);
        };

        /* Open reports a ciphertext shorter than the tag as a decryption failure,
         * however little room the output has */
        {
            DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
            EXPECT_OK(s2n_hpke_test_pair_init(&pair, ech_aeads[i], &info));
            EXPECT_OK(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                    S2N_HPKE_KDF_HKDF_SHA256, ech_aeads[i], &pair.enc, &info));

            uint8_t short_ct_bytes[15] = { 0 };
            uint8_t out_bytes[1] = { 0 };
            for (size_t len = 0; len <= sizeof(short_ct_bytes); len++) {
                struct s2n_blob short_ct = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&short_ct, short_ct_bytes, len));
                struct s2n_blob out_blob = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&out_blob, out_bytes, sizeof(out_bytes)));
                struct s2n_stuffer out = { 0 };
                EXPECT_SUCCESS(s2n_stuffer_init(&out, &out_blob));
                EXPECT_ERROR_WITH_ERRNO(s2n_hpke_open(pair.recipient, &aad, &short_ct, &out), S2N_ERR_DECRYPT);
                EXPECT_EQUAL(s2n_stuffer_data_available(&out), 0);
            }
        };
    }

    /* Setup rejects suites that ECH does not use. The recipient's KDF and AEAD come
     * from the peer, so an unsupported one is a decryption failure there. */
    {
        DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
        EXPECT_OK(s2n_hpke_test_pair_init(&pair, S2N_HPKE_AEAD_AES_128_GCM, &info));

        /* HKDF-SHA384 */
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                                        0x0002, S2N_HPKE_AEAD_AES_128_GCM, &pair.enc, &info),
                S2N_ERR_DECRYPT);
        /* Export-only */
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_setup_recipient(pair.recipient, pair.recipient_key,
                                        S2N_HPKE_KDF_HKDF_SHA256, 0xFFFF, &pair.enc, &info),
                S2N_ERR_DECRYPT);

        uint8_t peer_public_key_bytes[S2N_HPKE_X25519_PUBLIC_KEY_LEN] = { 0 };
        struct s2n_blob peer_public_key = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&peer_public_key, peer_public_key_bytes, sizeof(peer_public_key_bytes)));
        EXPECT_OK(s2n_hpke_key_public_key(pair.recipient_key, &peer_public_key));
        /* ML-KEM-768 */
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_setup_sender(pair.sender, 0x0041, S2N_HPKE_KDF_HKDF_SHA256,
                                        S2N_HPKE_AEAD_AES_128_GCM, &peer_public_key, &info, &pair.enc),
                S2N_ERR_INVALID_ARGUMENT);

        DEFER_CLEANUP(struct s2n_hpke_key *key = NULL, s2n_hpke_key_free);
        EXPECT_OK(s2n_hpke_key_new(&key));
        /* DHKEM(P-256, HKDF-SHA256) */
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_key_generate(key, 0x0010), S2N_ERR_INVALID_ARGUMENT);
    };

    /* A context cannot be used before it is set up */
    {
        DEFER_CLEANUP(struct s2n_hpke_ctx *ctx = NULL, s2n_hpke_ctx_free);
        EXPECT_OK(s2n_hpke_ctx_new(&ctx));

        uint16_t overhead = 0;
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_max_overhead(ctx, &overhead), S2N_ERR_INVALID_STATE);

        DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_seal(ctx, &aad, &pt, &out), S2N_ERR_INVALID_STATE);
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_open(ctx, &aad, &pt, &out), S2N_ERR_INVALID_STATE);
    };

    /* A key cannot be used before it is initialized */
    {
        DEFER_CLEANUP(struct s2n_hpke_key *key = NULL, s2n_hpke_key_free);
        EXPECT_OK(s2n_hpke_key_new(&key));

        uint8_t public_key_bytes[S2N_HPKE_X25519_PUBLIC_KEY_LEN] = { 0 };
        struct s2n_blob public_key = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&public_key, public_key_bytes, sizeof(public_key_bytes)));
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_key_public_key(key, &public_key), S2N_ERR_INVALID_STATE);

        DEFER_CLEANUP(struct s2n_hpke_ctx *ctx = NULL, s2n_hpke_ctx_free);
        EXPECT_OK(s2n_hpke_ctx_new(&ctx));
        uint8_t enc_bytes[S2N_HPKE_X25519_ENC_LEN] = { 0 };
        struct s2n_blob enc = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&enc, enc_bytes, sizeof(enc_bytes)));
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_setup_recipient(ctx, key, S2N_HPKE_KDF_HKDF_SHA256,
                                        S2N_HPKE_AEAD_AES_128_GCM, &enc, &info),
                S2N_ERR_INVALID_STATE);
    };

    /* Initializing or generating over a key replaces its key material.
     * AWS-LC releases that store key material out of line leak the old key
     * unless it is cleaned up first, which the leak checkers catch here. */
    {
        S2N_BLOB_FROM_HEX(sk_a, s2n_hpke_test_vectors[0].sk_r);
        S2N_BLOB_FROM_HEX(pk_a, s2n_hpke_test_vectors[0].pk_r);
        S2N_BLOB_FROM_HEX(sk_b, s2n_hpke_test_vectors[1].sk_r);
        S2N_BLOB_FROM_HEX(pk_b, s2n_hpke_test_vectors[1].pk_r);

        DEFER_CLEANUP(struct s2n_hpke_key *key = NULL, s2n_hpke_key_free);
        EXPECT_OK(s2n_hpke_key_new(&key));
        uint8_t public_key_bytes[S2N_HPKE_X25519_PUBLIC_KEY_LEN] = { 0 };
        struct s2n_blob public_key = { 0 };

        EXPECT_OK(s2n_hpke_key_init(key, S2N_HPKE_KEM_X25519_HKDF_SHA256, &sk_a));
        EXPECT_OK(s2n_hpke_key_init(key, S2N_HPKE_KEM_X25519_HKDF_SHA256, &sk_b));
        EXPECT_SUCCESS(s2n_blob_init(&public_key, public_key_bytes, sizeof(public_key_bytes)));
        EXPECT_OK(s2n_hpke_key_public_key(key, &public_key));
        S2N_BLOB_EXPECT_EQUAL(public_key, pk_b);

        EXPECT_OK(s2n_hpke_key_generate(key, S2N_HPKE_KEM_X25519_HKDF_SHA256));
        EXPECT_SUCCESS(s2n_blob_init(&public_key, public_key_bytes, sizeof(public_key_bytes)));
        EXPECT_OK(s2n_hpke_key_public_key(key, &public_key));
        EXPECT_EQUAL(public_key.size, pk_b.size);
        EXPECT_BYTEARRAY_NOT_EQUAL(public_key.data, pk_b.data, pk_b.size);

        EXPECT_OK(s2n_hpke_key_init(key, S2N_HPKE_KEM_X25519_HKDF_SHA256, &sk_a));
        EXPECT_SUCCESS(s2n_blob_init(&public_key, public_key_bytes, sizeof(public_key_bytes)));
        EXPECT_OK(s2n_hpke_key_public_key(key, &public_key));
        S2N_BLOB_EXPECT_EQUAL(public_key, pk_a);
    };

    /* A private key must be the X25519 length */
    {
        DEFER_CLEANUP(struct s2n_hpke_key *key = NULL, s2n_hpke_key_free);
        EXPECT_OK(s2n_hpke_key_new(&key));
        uint8_t sk_bytes[S2N_HPKE_X25519_PRIVATE_KEY_LEN + 1] = { 1 };
        const uint32_t wrong_lens[] = { 0, S2N_HPKE_X25519_PRIVATE_KEY_LEN - 1, S2N_HPKE_X25519_PRIVATE_KEY_LEN + 1 };
        for (size_t i = 0; i < s2n_array_len(wrong_lens); i++) {
            struct s2n_blob sk = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&sk, sk_bytes, wrong_lens[i]));
            EXPECT_ERROR_WITH_ERRNO(s2n_hpke_key_init(key, S2N_HPKE_KEM_X25519_HKDF_SHA256, &sk),
                    S2N_ERR_INVALID_ARGUMENT);
        }
    };

    /* The public key needs room for the X25519 length */
    {
        DEFER_CLEANUP(struct s2n_hpke_key *key = NULL, s2n_hpke_key_free);
        EXPECT_OK(s2n_hpke_key_new(&key));
        EXPECT_OK(s2n_hpke_key_generate(key, S2N_HPKE_KEM_X25519_HKDF_SHA256));
        uint8_t public_key_bytes[S2N_HPKE_X25519_PUBLIC_KEY_LEN - 1] = { 0 };
        struct s2n_blob public_key = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&public_key, public_key_bytes, sizeof(public_key_bytes)));
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_key_public_key(key, &public_key), S2N_ERR_INSUFFICIENT_MEM_SIZE);
        EXPECT_EQUAL(public_key.size, sizeof(public_key_bytes));
    };

    /* The seeded sender lets the caller choose the ephemeral key, so it only works in unit tests */
    {
        DEFER_CLEANUP(struct s2n_hpke_test_pair pair = { 0 }, s2n_hpke_test_pair_free);
        EXPECT_OK(s2n_hpke_test_pair_init(&pair, S2N_HPKE_AEAD_AES_128_GCM, &info));
        S2N_BLOB_FROM_HEX(seed, s2n_hpke_test_vectors[0].sk_e);
        S2N_BLOB_FROM_HEX(pk_r, s2n_hpke_test_vectors[0].pk_r);
        uint8_t enc_bytes[S2N_HPKE_X25519_ENC_LEN] = { 0 };
        struct s2n_blob enc = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&enc, enc_bytes, sizeof(enc_bytes)));

        EXPECT_SUCCESS(s2n_in_unit_test_set(false));
        EXPECT_ERROR_WITH_ERRNO(s2n_hpke_setup_sender_with_seed(pair.sender, S2N_HPKE_KEM_X25519_HKDF_SHA256,
                                        S2N_HPKE_KDF_HKDF_SHA256, S2N_HPKE_AEAD_AES_128_GCM, &pk_r, &info, &seed, &enc),
                S2N_ERR_NOT_IN_UNIT_TEST);
        EXPECT_SUCCESS(s2n_in_unit_test_set(true));

        EXPECT_OK(s2n_hpke_setup_sender_with_seed(pair.sender, S2N_HPKE_KEM_X25519_HKDF_SHA256,
                S2N_HPKE_KDF_HKDF_SHA256, S2N_HPKE_AEAD_AES_128_GCM, &pk_r, &info, &seed, &enc));
    };

    /* Freeing a NULL key or context is a no-op */
    {
        struct s2n_hpke_key *key = NULL;
        EXPECT_OK(s2n_hpke_key_free(&key));
        struct s2n_hpke_ctx *ctx = NULL;
        EXPECT_OK(s2n_hpke_ctx_free(&ctx));
    };

    END_TEST();
}
