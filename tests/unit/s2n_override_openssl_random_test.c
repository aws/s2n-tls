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

#include <openssl/dh.h>

#include "api/s2n.h"
#include "crypto/s2n_dhe.h"
#include "crypto/s2n_drbg.h"
#include "crypto/s2n_ecc_evp.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

const char reference_entropy_hex[] = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                     "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                     "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                                     "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/**
 * This test verifies that s2n can override OpenSSL's RNG with s2n's RNG implementation. We do that by initializing s2n's
 * RNG with all zeros, overriding OpenSSL's RNG with s2n's, generating a DH Param, and verifying that the DH param
 * matches a known hex string.
 */
const char *expected_dhe_key_hexes[] = {
    "0100cb5fa155609f350a0f07e340ef7dc854e38d97c7c2ba68b3f7375146ed61cd56b6caf1ac7944aa05b9fa934150ef23040fac395d640a0c2d33da6d0523f04"
    "f13702351fb8fcc4606a930dff73419d8bcf8a0037dd12b9d96e3a8121611f7d7046c29f44f8781bc47fd214b5ccd7519ff08fb83319b186d3b74b7d3f8298244"
    "9c428e1ae8b1e9c9833b9cc92ee3b756e86e053ae892a480c366ee1258e3f9e14792d64c2cd9cb36108761ccd959382b966a20ba63fe7d12e496134363d58713f"
    "e52ef3e8480acffc56f33bd83ce78cf673b9f0038a98c2ec2b10e12eb1fde71996e16d6dbf994ef1c8e429d89a403027af8549619a6500e2f1b81eac593d456c3"
    "00010201001d255a7d1afbf0c706fd776a51e34074e0c0b86a1fdbafd6b893ea7e71ffe91de204f787836592c20bbafc71bfcfb38478827826e2fc76db25e263a"
    "3c8e1c74d46344d3ef8939ec663e29de34698138d0a28fcf00bc0a65380c1ac58ee7d2d94f343bd94cb558bb6b30d24ca6465cae259239487b2e8796a9e54b518"
    "4f4c78f3c31c27e091530da9e261d407b42da97718b6b44c9ca8a4cc74d3b6c43573051a97ec2cbf938f32fbb108e9f3cb397471fc2d3edaef46225e63720564b"
    "ddbaa47646a497793e0a8e129e00e4fcd4b11b68897afb0987a48f51e3a3079e3d0573d340597c2c7b8ec839ea608a341c8d3ae8fb8a30c2d80e7083f64adf790"
    "18a19c",
    /* Openssl-3.5.3 slightly changed how keys were calculated, resulting in a different
     * expected value for this test.
     * See https://github.com/openssl/openssl/commit/d6510d99ae4a8a23f54fdfb1473af6a920da8345Z
     */
    "0100CB5FA155609F350A0F07E340EF7DC854E38D97C7C2BA68B3F7375146ED61CD56B6CAF1AC7944AA05B9FA934150EF23040FAC395D640A0C2D33DA6D0523F04"
    "F13702351FB8FCC4606A930DFF73419D8BCF8A0037DD12B9D96E3A8121611F7D7046C29F44F8781BC47FD214B5CCD7519FF08FB83319B186D3B74B7D3F8298244"
    "9C428E1AE8B1E9C9833B9CC92EE3B756E86E053AE892A480C366EE1258E3F9E14792D64C2CD9CB36108761CCD959382B966A20BA63FE7D12E496134363D58713F"
    "E52EF3E8480ACFFC56F33BD83CE78CF673B9F0038A98C2EC2B10E12EB1FDE71996E16D6DBF994EF1C8E429D89A403027AF8549619A6500E2F1B81EAC593D456C3"
    "00010201007D5E191DE28BF3E2973F3F3B9C3F493A9A1C5A6BBEEEEFB1E206214A3844EE417D3BE0F0E58FA793B6A0098A8304B51063B682548846351BF7ABD0D"
    "E6B895B27F798C3972DAAE4BCC6AE390E60E1DF3505DC192704154550174237415F26BE5A6CE8481AC5AFAF8F97BACE8F728286C26F701B77CD2FDC7BAE17770B"
    "7ED373DED91B572752F496CAA37BDDF6E93D75BA2D20DB967184386A8F257B193703A9789FCFFC28F70E3BD71B58E8BE6D5E3A438EFAE5C4C91FD5CD4D341D352"
    "F438D30EE7FB65257118CD723F048EBF79D4850C17B3276D7E8C07F80734E20B3CF60F08A6767787BE22C882CEB7C5A32D00FC48EC64830978B0C9C9CCF92A45E"
    "EF8055",
};

struct s2n_stuffer test_entropy = { 0 };
int s2n_entropy_generator(void *data, uint32_t size)
{
    struct s2n_blob blob = { 0 };
    POSIX_GUARD(s2n_blob_init(&blob, data, size));
    POSIX_GUARD(s2n_stuffer_read(&test_entropy, &blob));
    return 0;
}

int s2n_entropy_init_cleanup(void)
{
    return 0;
}

int main(int argc, char **argv)
{
    struct s2n_stuffer dhparams_in = { 0 }, dhparams_out = { 0 };
    struct s2n_dh_params dh_params = { 0 };
    struct s2n_blob b = { 0 };
    char *dhparams_pem = NULL;
    uint64_t bytes_used = 0;

    BEGIN_TEST();

    if (!s2n_supports_custom_rand()) {
        /* Skip when custom rand is not supported */
        END_TEST();
    }

    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_OK(s2n_get_private_random_bytes_used(&bytes_used));
    EXPECT_EQUAL(bytes_used, 0);

    /* Parse the DH params */
    EXPECT_SUCCESS(s2n_blob_init(&b, (uint8_t *) dhparams_pem, strlen(dhparams_pem) + 1));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_in, b.size));
    EXPECT_SUCCESS(s2n_stuffer_alloc(&dhparams_out, b.size));
    EXPECT_SUCCESS(s2n_stuffer_write(&dhparams_in, &b));
    EXPECT_SUCCESS(s2n_stuffer_dhparams_from_pem(&dhparams_in, &dhparams_out));
    uint32_t available_size = s2n_stuffer_data_available(&dhparams_out);
    EXPECT_SUCCESS(s2n_blob_init(&b, s2n_stuffer_raw_read(&dhparams_out, available_size), available_size));
    EXPECT_SUCCESS(s2n_pkcs3_to_dh_params(&dh_params, &b));

    EXPECT_SUCCESS(s2n_dh_generate_ephemeral_key(&dh_params));

    /* Verify that our DRBG is called and that over-riding works */
    EXPECT_OK(s2n_get_private_random_bytes_used(&bytes_used));
    EXPECT_NOT_EQUAL(bytes_used, 0);

    /* Setup for the second test */
    EXPECT_SUCCESS(s2n_dh_params_free(&dh_params));
    EXPECT_SUCCESS(s2n_pkcs3_to_dh_params(&dh_params, &b));

    /* Set s2n_random to use a new fixed DRBG to test that other known answer tests with s2n_random and OpenSSL are deterministic */
    EXPECT_OK(s2n_stuffer_alloc_from_hex(&test_entropy, reference_entropy_hex));
    struct s2n_drbg drbg;

    POSIX_GUARD_RESULT(s2n_rand_cleanup());
    EXPECT_SUCCESS(s2n_rand_set_callbacks(s2n_entropy_init_cleanup, s2n_entropy_init_cleanup, s2n_entropy_generator, s2n_entropy_generator));
    POSIX_GUARD_RESULT(s2n_rand_init());

    s2n_stack_blob(personalization_string, 32, 32);
    EXPECT_OK(s2n_drbg_instantiate(&drbg, &personalization_string, S2N_AES_256_CTR_NO_DF_PR));
    EXPECT_OK(s2n_set_private_drbg_for_test(drbg));
    /* Verify we switched to a new DRBG */
    EXPECT_OK(s2n_get_private_random_bytes_used(&bytes_used));
    EXPECT_EQUAL(bytes_used, 0);

    DEFER_CLEANUP(struct s2n_stuffer out_stuffer = { 0 }, s2n_stuffer_free);
    struct s2n_blob out_blob = { 0 };
    EXPECT_SUCCESS(s2n_stuffer_alloc(&out_stuffer, 4096));
    POSIX_GUARD(s2n_dh_generate_ephemeral_key(&dh_params));
    POSIX_GUARD(s2n_dh_params_to_p_g_Ys(&dh_params, &out_stuffer, &out_blob));
    EXPECT_EQUAL(out_blob.size, 519);

    EXPECT_OK(s2n_get_private_random_bytes_used(&bytes_used));
    EXPECT_EQUAL(bytes_used, 352);

    /* Different libcryptos produce different results.
     * We just need one result to match.
     */
    bool key_match = false;
    for (size_t i = 0; i < s2n_array_len(expected_dhe_key_hexes); i++) {
        S2N_BLOB_FROM_HEX(expected_dhe_key_hex, expected_dhe_key_hexes[i]);
        EXPECT_EQUAL(expected_dhe_key_hex.size, 519);
        key_match = (0 == memcmp(expected_dhe_key_hex.data, out_blob.data, out_blob.size));
        if (key_match) {
            break;
        }
    }
    EXPECT_TRUE(key_match);

    EXPECT_SUCCESS(s2n_dh_params_free(&dh_params));
    EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_out));
    EXPECT_SUCCESS(s2n_stuffer_free(&dhparams_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&test_entropy));
    free(dhparams_pem);

    END_TEST();
}
