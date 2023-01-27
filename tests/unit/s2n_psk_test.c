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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

/* Include source to test static intermediate functions */
#include "tls/s2n_psk.c"

#define TEST_VALUE_1 "test value"
#define TEST_VALUE_2 "another"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_psk_init */
    {
        EXPECT_ERROR_WITH_ERRNO(s2n_psk_init(NULL, S2N_PSK_TYPE_EXTERNAL),
                S2N_ERR_NULL);

        DEFER_CLEANUP(struct s2n_psk psk, s2n_psk_wipe);

        EXPECT_OK(s2n_psk_init(&psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_EQUAL(psk.type, S2N_PSK_TYPE_EXTERNAL);
        EXPECT_EQUAL(psk.hmac_alg, S2N_HMAC_SHA256);
        EXPECT_EQUAL(psk.ticket_age_add, 0);
        EXPECT_EQUAL(psk.ticket_issue_time, 0);
        EXPECT_EQUAL(psk.early_data_config.max_early_data_size, 0);

        EXPECT_OK(s2n_psk_init(&psk, S2N_PSK_TYPE_RESUMPTION));
        EXPECT_EQUAL(psk.type, S2N_PSK_TYPE_RESUMPTION);
        EXPECT_EQUAL(psk.hmac_alg, S2N_HMAC_SHA256);
        EXPECT_EQUAL(psk.ticket_age_add, 0);
        EXPECT_EQUAL(psk.ticket_issue_time, 0);
        EXPECT_EQUAL(psk.early_data_config.max_early_data_size, 0);
    };

    /* Test s2n_external_psk_new */
    {
        DEFER_CLEANUP(struct s2n_psk inited_psk, s2n_psk_wipe);
        EXPECT_OK(s2n_psk_init(&inited_psk, S2N_PSK_TYPE_EXTERNAL));

        DEFER_CLEANUP(struct s2n_psk *new_psk = s2n_external_psk_new(), s2n_psk_free);
        EXPECT_NOT_NULL(new_psk);

        EXPECT_BYTEARRAY_EQUAL(new_psk, &inited_psk, sizeof(struct s2n_psk));
    };

    /* Test s2n_psk_set_identity */
    {
        DEFER_CLEANUP(struct s2n_psk psk, s2n_psk_wipe);
        EXPECT_OK(s2n_psk_init(&psk, S2N_PSK_TYPE_EXTERNAL));

        uint8_t test_value_1[] = TEST_VALUE_1;

        EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_identity(NULL, test_value_1, 1),
                S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_identity(&psk, NULL, 1),
                S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_identity(&psk, test_value_1, 0),
                S2N_ERR_INVALID_ARGUMENT);

        EXPECT_SUCCESS(s2n_psk_set_identity(&psk, test_value_1, sizeof(test_value_1)));
        EXPECT_EQUAL(psk.identity.size, sizeof(TEST_VALUE_1));
        EXPECT_BYTEARRAY_EQUAL(psk.identity.data, TEST_VALUE_1, sizeof(TEST_VALUE_1));

        /* source can be modified without affecting psk */
        test_value_1[0] = 'A';
        EXPECT_BYTEARRAY_EQUAL(psk.identity.data, TEST_VALUE_1, sizeof(TEST_VALUE_1));

        /* method can be called again to replace identity */
        uint8_t test_value_2[] = TEST_VALUE_2;
        EXPECT_SUCCESS(s2n_psk_set_identity(&psk, test_value_2, sizeof(test_value_2)));
        EXPECT_EQUAL(psk.identity.size, sizeof(TEST_VALUE_2));
        EXPECT_BYTEARRAY_EQUAL(psk.identity.data, TEST_VALUE_2, sizeof(TEST_VALUE_2));
    };

    /* Test s2n_psk_set_secret */
    {
        DEFER_CLEANUP(struct s2n_psk psk, s2n_psk_wipe);
        EXPECT_OK(s2n_psk_init(&psk, S2N_PSK_TYPE_EXTERNAL));

        uint8_t test_value_1[] = TEST_VALUE_1;

        EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_secret(NULL, test_value_1, 1),
                S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_secret(&psk, NULL, 1),
                S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_secret(&psk, test_value_1, 0),
                S2N_ERR_INVALID_ARGUMENT);

        EXPECT_SUCCESS(s2n_psk_set_secret(&psk, test_value_1, sizeof(test_value_1)));
        EXPECT_EQUAL(psk.secret.size, sizeof(TEST_VALUE_1));
        EXPECT_BYTEARRAY_EQUAL(psk.secret.data, TEST_VALUE_1, sizeof(TEST_VALUE_1));

        /* source identity can be modified without affecting psk */
        test_value_1[0] = 'A';
        EXPECT_BYTEARRAY_EQUAL(psk.secret.data, TEST_VALUE_1, sizeof(TEST_VALUE_1));

        /* method can be called again to replace secret */
        uint8_t test_value_2[] = TEST_VALUE_2;
        EXPECT_SUCCESS(s2n_psk_set_secret(&psk, test_value_2, sizeof(test_value_2)));
        EXPECT_EQUAL(psk.secret.size, sizeof(TEST_VALUE_2));
        EXPECT_BYTEARRAY_EQUAL(psk.secret.data, TEST_VALUE_2, sizeof(TEST_VALUE_2));
    };

    /* Test s2n_psk_clone */
    {
        const uint8_t test_bad_value[] = "wrong";
        const uint8_t test_identity[] = "identity";
        const uint8_t test_secret[] = "secret";
        const uint8_t test_early_secret[] = "early_secret";
        const s2n_hmac_algorithm test_hmac = S2N_HMAC_SHA384;

        struct s2n_psk *original = s2n_external_psk_new();
        EXPECT_NOT_NULL(original);
        EXPECT_SUCCESS(s2n_psk_set_identity(original, test_identity, sizeof(test_identity)));
        EXPECT_SUCCESS(s2n_psk_set_secret(original, test_secret, sizeof(test_secret)));
        EXPECT_SUCCESS(s2n_alloc(&original->early_secret, sizeof(test_early_secret)));
        EXPECT_MEMCPY_SUCCESS(original->early_secret.data, test_early_secret, original->early_secret.size);
        original->hmac_alg = test_hmac;

        DEFER_CLEANUP(struct s2n_psk *clone = s2n_external_psk_new(), s2n_psk_free);
        EXPECT_SUCCESS(s2n_psk_set_identity(clone, test_bad_value, sizeof(test_bad_value)));
        EXPECT_SUCCESS(s2n_psk_set_secret(clone, test_bad_value, sizeof(test_bad_value)));
        EXPECT_NOT_NULL(clone);

        /* Check that the blobs weren't shallow copied */
        EXPECT_NOT_EQUAL(original->identity.data, clone->identity.data);
        EXPECT_NOT_EQUAL(original->secret.data, clone->secret.data);
        EXPECT_NOT_EQUAL(original->early_secret.data, clone->early_secret.data);

        EXPECT_OK(s2n_psk_clone(clone, original));

        /* Free the original to ensure they share no memory */
        EXPECT_SUCCESS(s2n_psk_free(&original));

        /* existing identity is replaced by original's identity */
        EXPECT_EQUAL(clone->identity.size, sizeof(test_identity));
        EXPECT_BYTEARRAY_EQUAL(clone->identity.data, test_identity, sizeof(test_identity));

        /* new secret is replaced by original's secret */
        EXPECT_EQUAL(clone->secret.size, sizeof(test_secret));
        EXPECT_BYTEARRAY_EQUAL(clone->secret.data, test_secret, sizeof(test_secret));

        /* early secret is allocated for original's early secret */
        EXPECT_EQUAL(clone->early_secret.size, sizeof(test_early_secret));
        EXPECT_BYTEARRAY_EQUAL(clone->early_secret.data, test_early_secret, sizeof(test_early_secret));

        /* other values are copied */
        EXPECT_EQUAL(clone->hmac_alg, test_hmac);
    };

    /* Test s2n_psk_wipe */
    {
        const uint8_t test_value[] = TEST_VALUE_1;
        struct s2n_psk psk = { 0 };
        EXPECT_OK(s2n_psk_init(&psk, S2N_PSK_TYPE_EXTERNAL));

        /* No-op if blobs not allocated yet */
        EXPECT_OK(s2n_psk_wipe(&psk));

        EXPECT_SUCCESS(s2n_psk_set_identity(&psk, test_value, sizeof(test_value)));
        EXPECT_NOT_EQUAL(psk.identity.size, 0);
        EXPECT_SUCCESS(s2n_psk_set_secret(&psk, test_value, sizeof(test_value)));
        EXPECT_NOT_EQUAL(psk.secret.size, 0);
        EXPECT_SUCCESS(s2n_alloc(&psk.early_secret, sizeof(test_value)));
        EXPECT_NOT_EQUAL(psk.early_secret.size, 0);

        /* Frees all blobs */
        EXPECT_OK(s2n_psk_wipe(&psk));
        EXPECT_EQUAL(psk.identity.data, NULL);
        EXPECT_EQUAL(psk.identity.size, 0);
        EXPECT_EQUAL(psk.secret.data, NULL);
        EXPECT_EQUAL(psk.secret.size, 0);
        EXPECT_EQUAL(psk.early_secret.data, NULL);
        EXPECT_EQUAL(psk.early_secret.size, 0);

        /* No-op if already freed */
        EXPECT_OK(s2n_psk_wipe(&psk));
    };

    /* Test s2n_psk_free */
    {
        EXPECT_SUCCESS(s2n_psk_free(NULL));

        struct s2n_psk *new_psk = s2n_external_psk_new();
        EXPECT_NOT_NULL(new_psk);
        EXPECT_SUCCESS(s2n_psk_free(&new_psk));
        EXPECT_NULL(new_psk);
    };

    /* Test s2n_psk_parameters_init */
    {
        DEFER_CLEANUP(struct s2n_psk_parameters params, s2n_psk_parameters_wipe);

        EXPECT_ERROR_WITH_ERRNO(s2n_psk_parameters_init(NULL), S2N_ERR_NULL);

        EXPECT_OK(s2n_psk_parameters_init(&params));

        /* Verify params are initialized.
         * Only element_size should be set. */
        struct s2n_psk_parameters expected_params = { 0 };
        expected_params.psk_list.element_size = sizeof(struct s2n_psk);
        EXPECT_BYTEARRAY_EQUAL(&expected_params, &params, sizeof(struct s2n_psk_parameters));
    };

    /* Test s2n_psk_parameters_wipe */
    {
        uint8_t test_value[] = TEST_VALUE_1;

        DEFER_CLEANUP(struct s2n_psk_parameters params = { 0 }, s2n_psk_parameters_wipe);
        EXPECT_OK(s2n_psk_parameters_init(&params));
        params.binder_list_size = 1;
        params.chosen_psk_wire_index = 1;

        struct s2n_psk *chosen_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&params.psk_list, (void **) &chosen_psk));
        EXPECT_OK(s2n_psk_init(chosen_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(chosen_psk, test_value, sizeof(test_value)));
        params.chosen_psk = chosen_psk;

        struct s2n_psk *other_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&params.psk_list, (void **) &other_psk));
        EXPECT_OK(s2n_psk_init(other_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(other_psk, test_value, sizeof(test_value)));

        EXPECT_ERROR_WITH_ERRNO(s2n_psk_parameters_wipe(NULL), S2N_ERR_NULL);
        EXPECT_OK(s2n_psk_parameters_wipe(&params));

        /* Verify params are wiped.
         * The params should be back to their initial state. */
        struct s2n_psk_parameters expected_params = { 0 };
        EXPECT_OK(s2n_psk_parameters_init(&expected_params));
        EXPECT_BYTEARRAY_EQUAL(&expected_params, &params, sizeof(struct s2n_psk_parameters));
    };

    /* Test s2n_psk_parameters_wipe_secrets */
    {
        /* Safety Check */
        EXPECT_ERROR_WITH_ERRNO(s2n_psk_parameters_wipe_secrets(NULL), S2N_ERR_NULL);

        uint8_t test_identity_data[] = "test identity data";
        uint8_t test_secret_data[] = "test secret data";
        struct s2n_psk_parameters params = { 0 };
        EXPECT_OK(s2n_psk_parameters_init(&params));
        params.binder_list_size = 1;
        params.chosen_psk_wire_index = 1;

        struct s2n_psk *chosen_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&params.psk_list, (void **) &chosen_psk));
        EXPECT_OK(s2n_psk_init(chosen_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(chosen_psk, test_identity_data, sizeof(test_identity_data)));
        EXPECT_SUCCESS(s2n_psk_set_secret(chosen_psk, test_secret_data, sizeof(test_secret_data)));
        params.chosen_psk = chosen_psk;

        struct s2n_psk *other_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&params.psk_list, (void **) &other_psk));
        EXPECT_OK(s2n_psk_init(other_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(other_psk, test_identity_data, sizeof(test_identity_data)));
        EXPECT_SUCCESS(s2n_psk_set_secret(other_psk, test_secret_data, sizeof(test_secret_data)));

        EXPECT_OK(s2n_psk_parameters_wipe_secrets(&params));

        /* Verify secrets are wiped */
        for (size_t i = 0; i < params.psk_list.len; i++) {
            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_get(&params.psk_list, i, (void **) &psk));
            EXPECT_NOT_NULL(psk->identity.data);
            EXPECT_NULL(psk->secret.data);
            EXPECT_EQUAL(psk->secret.size, 0);
            EXPECT_NULL(psk->early_secret.data);
            EXPECT_EQUAL(psk->early_secret.size, 0);
        }

        EXPECT_OK(s2n_psk_parameters_wipe(&params));
    };

    /* Test s2n_connection psk_parameters lifecycle.
     * This test mostly exists to check for memory leaks. */
    {
        uint8_t test_value[] = TEST_VALUE_1;
        struct s2n_psk_parameters empty_psk_params = { 0 };
        EXPECT_OK(s2n_psk_parameters_init(&empty_psk_params));

        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        conn->psk_params.binder_list_size = 1;
        conn->psk_params.chosen_psk_wire_index = 1;

        struct s2n_psk *first_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &first_psk));
        EXPECT_OK(s2n_psk_init(first_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(first_psk, test_value, sizeof(test_value)));
        conn->psk_params.chosen_psk = first_psk;

        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        EXPECT_BYTEARRAY_EQUAL(&empty_psk_params, &conn->psk_params, sizeof(struct s2n_psk_parameters));

        struct s2n_psk *second_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &second_psk));
        EXPECT_OK(s2n_psk_init(second_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(second_psk, test_value, sizeof(test_value)));
        conn->psk_params.chosen_psk = second_psk;

        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        EXPECT_BYTEARRAY_EQUAL(&empty_psk_params, &conn->psk_params, sizeof(struct s2n_psk_parameters));

        struct s2n_psk *third_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &third_psk));
        EXPECT_OK(s2n_psk_init(third_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(third_psk, test_value, sizeof(test_value)));
        conn->psk_params.chosen_psk = third_psk;

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_psk_write_binder_list */
    {
        uint8_t test_value[] = TEST_VALUE_1;

        struct s2n_blob client_hello_prefix = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&client_hello_prefix, test_value, sizeof(test_value)));

        /* Write two binders.
         * There are no available test vectors for multiple PSKs, but we should at least
         * verify that we write something relatively sane for this use case. */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_psk_parameters *params = &conn->psk_params;

            struct s2n_psk *first_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&params->psk_list, (void **) &first_psk));
            EXPECT_OK(s2n_psk_init(first_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_secret(first_psk, test_value, sizeof(test_value)));

            struct s2n_psk *second_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&params->psk_list, (void **) &second_psk));
            EXPECT_OK(s2n_psk_init(second_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_secret(second_psk, test_value, sizeof(test_value)));

            EXPECT_OK(s2n_psk_write_binder_list(conn, &client_hello_prefix, &out));

            uint16_t binder_list_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &binder_list_size));
            EXPECT_EQUAL(binder_list_size, s2n_stuffer_data_available(&out));

            /* After reading both binders, the buffer should be empty. */
            for (int i = 0; i < 2; i++) {
                uint8_t binder_size = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &binder_size));
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&out, binder_size));
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&out), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        };

        /* On a retry, do not write binders for PSKs that do not match the cipher suite.
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.1.4
         *= type=test
         *# In addition, in its updated ClientHello, the client SHOULD NOT offer
         *# any pre-shared keys associated with a hash other than that of the
         *# selected cipher suite.  This allows the client to avoid having to
         *# compute partial hash transcripts for multiple hashes in the second
         *# ClientHello.
         */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            conn->handshake.handshake_type = HELLO_RETRY_REQUEST;
            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_psk_parameters *params = &conn->psk_params;

            struct s2n_psk *other_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&params->psk_list, (void **) &other_psk));
            EXPECT_OK(s2n_psk_init(other_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_secret(other_psk, test_value, sizeof(test_value)));
            other_psk->hmac_alg = conn->secure->cipher_suite->prf_alg - 1;

            struct s2n_psk *matching_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&params->psk_list, (void **) &matching_psk));
            EXPECT_OK(s2n_psk_init(matching_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_secret(matching_psk, test_value, sizeof(test_value)));
            matching_psk->hmac_alg = conn->secure->cipher_suite->prf_alg;

            EXPECT_OK(s2n_psk_write_binder_list(conn, &client_hello_prefix, &out));

            uint16_t binder_list_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &binder_list_size));
            EXPECT_EQUAL(binder_list_size, s2n_stuffer_data_available(&out));

            /* There should only be one binder in the list
             * (the other PSK was ignored because it didn't match the cipher suite)
             * so that one binder should fill the rest of the stuffer. */
            uint8_t binder_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &binder_size));
            EXPECT_EQUAL(binder_size, s2n_stuffer_data_available(&out));

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }
    };

    /* Test binder calculations with known values */
    {
        /* Test Vectors from https://tools.ietf.org/html/rfc8448#section-4 */
        S2N_BLOB_FROM_HEX(identity,
                "2c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b00"
                "70ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3"
                "ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725"
                "a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda72"
                "1470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfb"
                "c388e93343694093934ae4d357fad6aacb");
        S2N_BLOB_FROM_HEX(client_hello_prefix,
                "010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d"
                "7876487d95000006130113031302010001cd0000000b0009000006736572766572"
                "ff01000100000a00140012001d0017001800190100010101020103010400330026"
                "0024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4"
                "f18d668f0b002a0000002b0003020304000d0020001e0403050306030203080408"
                "05080604010501060102010402050206020202002d00020101001c000240010015"
                "005700000000000000000000000000000000000000000000000000000000000000"
                "000000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000002900dd00b800b22c03"
                "5d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad"
                "3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5d"
                "d36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4"
                "dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470"
                "f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388"
                "e93343694093934ae4d357fad6aacb");
        S2N_BLOB_FROM_HEX(full_client_hello,
                "010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d"
                "7876487d95000006130113031302010001cd0000000b0009000006736572766572"
                "ff01000100000a00140012001d0017001800190100010101020103010400330026"
                "0024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4"
                "f18d668f0b002a0000002b0003020304000d0020001e0403050306030203080408"
                "05080604010501060102010402050206020202002d00020101001c000240010015"
                "005700000000000000000000000000000000000000000000000000000000000000"
                "000000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000000000000000002900dd00b800b22c03"
                "5d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad"
                "3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5d"
                "d36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4"
                "dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470"
                "f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388"
                "e93343694093934ae4d357fad6aacb0021203add4fb2d8fdf822a0ca3cf7678ef5"
                "e88dae990141c5924d57bb6fa31b9e5f9d");
        S2N_BLOB_FROM_HEX(resumption_secret,
                "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
        S2N_BLOB_FROM_HEX(binder_hash,
                "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");
        S2N_BLOB_FROM_HEX(early_secret,
                "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c");
        S2N_BLOB_FROM_HEX(finished_binder,
                "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d");

        /* Test s2n_psk_calculate_binder_hash with known values */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_blob hash_value = { 0 };
            uint8_t hash_value_data[SHA256_DIGEST_LENGTH];
            EXPECT_SUCCESS(s2n_blob_init(&hash_value, hash_value_data, sizeof(hash_value_data)));

            EXPECT_SUCCESS(s2n_psk_calculate_binder_hash(conn, S2N_HMAC_SHA256, &client_hello_prefix, &hash_value));
            S2N_BLOB_EXPECT_EQUAL(hash_value, binder_hash);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test s2n_psk_calculate_binder with known values */
        {
            DEFER_CLEANUP(struct s2n_psk test_psk, s2n_psk_wipe);
            EXPECT_OK(s2n_psk_init(&test_psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_set_secret(&test_psk, resumption_secret.data, resumption_secret.size));

            struct s2n_blob binder_value = { 0 };
            uint8_t binder_value_data[SHA256_DIGEST_LENGTH];
            EXPECT_SUCCESS(s2n_blob_init(&binder_value, binder_value_data, sizeof(binder_value_data)));

            EXPECT_SUCCESS(s2n_psk_calculate_binder(&test_psk, &binder_hash, &binder_value));
            S2N_BLOB_EXPECT_EQUAL(test_psk.early_secret, early_secret);
            S2N_BLOB_EXPECT_EQUAL(binder_value, finished_binder);
        };

        /* Test s2n_psk_verify_binder with known values */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            DEFER_CLEANUP(struct s2n_psk test_psk, s2n_psk_wipe);
            EXPECT_OK(s2n_psk_init(&test_psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_set_secret(&test_psk, resumption_secret.data, resumption_secret.size));

            struct s2n_blob binder_value = { 0 };
            uint8_t binder_value_data[SHA256_DIGEST_LENGTH];
            EXPECT_SUCCESS(s2n_blob_init(&binder_value, binder_value_data, sizeof(binder_value_data)));

            EXPECT_SUCCESS(s2n_psk_verify_binder(conn, &test_psk, &client_hello_prefix, &finished_binder));
            S2N_BLOB_EXPECT_EQUAL(test_psk.early_secret, early_secret);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test s2n_psk_verify_binder with incorrect binder */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            DEFER_CLEANUP(struct s2n_psk test_psk, s2n_psk_wipe);
            EXPECT_OK(s2n_psk_init(&test_psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_set_secret(&test_psk, resumption_secret.data, resumption_secret.size));

            struct s2n_blob *incorrect_binder_value = &resumption_secret;

            struct s2n_blob binder_value = { 0 };
            uint8_t binder_value_data[SHA256_DIGEST_LENGTH];
            EXPECT_SUCCESS(s2n_blob_init(&binder_value, binder_value_data, sizeof(binder_value_data)));

            EXPECT_FAILURE(s2n_psk_verify_binder(conn, &test_psk, &client_hello_prefix, incorrect_binder_value));
            S2N_BLOB_EXPECT_EQUAL(test_psk.early_secret, early_secret);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test s2n_psk_write_binder with known values */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            DEFER_CLEANUP(struct s2n_psk psk = { 0 }, s2n_psk_wipe);
            EXPECT_OK(s2n_psk_init(&psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_set_secret(&psk, resumption_secret.data, resumption_secret.size));

            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            EXPECT_OK(s2n_psk_write_binder(conn, &psk, &binder_hash, &out));

            uint8_t binder_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &binder_size));
            EXPECT_EQUAL(binder_size, s2n_stuffer_data_available(&out));
            EXPECT_EQUAL(binder_size, finished_binder.size);

            uint8_t *binder_data;
            EXPECT_NOT_NULL(binder_data = s2n_stuffer_raw_read(&out, binder_size));
            EXPECT_BYTEARRAY_EQUAL(binder_data, finished_binder.data, binder_size);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        };

        /* Test s2n_psk_write_binder_list with known values */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &psk));
            EXPECT_OK(s2n_psk_init(psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_set_identity(psk, identity.data, identity.size));
            EXPECT_SUCCESS(s2n_psk_set_secret(psk, resumption_secret.data, resumption_secret.size));

            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            EXPECT_OK(s2n_psk_write_binder_list(conn, &client_hello_prefix, &out));

            uint16_t binder_list_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &binder_list_size));
            EXPECT_EQUAL(binder_list_size, s2n_stuffer_data_available(&out));

            uint8_t binder_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &binder_size));
            EXPECT_EQUAL(binder_size, s2n_stuffer_data_available(&out));
            EXPECT_EQUAL(binder_size, finished_binder.size);

            uint8_t *binder_data;
            EXPECT_NOT_NULL(binder_data = s2n_stuffer_raw_read(&out, binder_size));
            EXPECT_BYTEARRAY_EQUAL(binder_data, finished_binder.data, binder_size);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        };

        /* Test s2n_psk_write_binder_list with multiple PSKs */
        {
            const uint8_t psk_count = 5;

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            for (uint8_t i = 0; i < psk_count; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &psk));
                EXPECT_OK(s2n_psk_init(psk, S2N_PSK_TYPE_RESUMPTION));
                EXPECT_SUCCESS(s2n_psk_set_identity(psk, identity.data, identity.size));
                EXPECT_SUCCESS(s2n_psk_set_secret(psk, resumption_secret.data, resumption_secret.size));
            }

            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            EXPECT_OK(s2n_psk_write_binder_list(conn, &client_hello_prefix, &out));

            uint16_t binder_list_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &binder_list_size));
            EXPECT_EQUAL(binder_list_size, s2n_stuffer_data_available(&out));

            for (uint8_t i = 0; i < psk_count; i++) {
                uint8_t binder_size = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &binder_size));
                EXPECT_EQUAL(binder_size, finished_binder.size);

                uint8_t *binder_data;
                EXPECT_NOT_NULL(binder_data = s2n_stuffer_raw_read(&out, binder_size));
                EXPECT_BYTEARRAY_EQUAL(binder_data, finished_binder.data, binder_size);
            }

            EXPECT_EQUAL(s2n_stuffer_data_available(&out), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        };

        /* Test s2n_psk_write_binder_list with multiple hash algs */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            for (s2n_hmac_algorithm hmac_alg = S2N_HMAC_SHA256; hmac_alg <= S2N_HMAC_SHA384; hmac_alg++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &psk));
                EXPECT_OK(s2n_psk_init(psk, S2N_PSK_TYPE_RESUMPTION));
                EXPECT_SUCCESS(s2n_psk_set_identity(psk, identity.data, identity.size));
                EXPECT_SUCCESS(s2n_psk_set_secret(psk, resumption_secret.data, resumption_secret.size));
                psk->hmac_alg = hmac_alg;
            }

            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            EXPECT_OK(s2n_psk_write_binder_list(conn, &client_hello_prefix, &out));

            uint16_t binder_list_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &binder_list_size));
            EXPECT_EQUAL(binder_list_size, s2n_stuffer_data_available(&out));

            for (s2n_hmac_algorithm hmac_alg = S2N_HMAC_SHA256; hmac_alg <= S2N_HMAC_SHA384; hmac_alg++) {
                uint8_t hash_size = 0;
                POSIX_GUARD(s2n_hmac_digest_size(hmac_alg, &hash_size));

                uint8_t binder_size = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint8(&out, &binder_size));
                EXPECT_EQUAL(binder_size, hash_size);

                uint8_t *binder_data;
                EXPECT_NOT_NULL(binder_data = s2n_stuffer_raw_read(&out, binder_size));
                /* We can only actually verify the result for SHA256; we don't have known
                 * values for any other hash. */
                if (hmac_alg == S2N_HMAC_SHA256) {
                    EXPECT_BYTEARRAY_EQUAL(binder_data, finished_binder.data, binder_size);
                }
            }

            EXPECT_EQUAL(s2n_stuffer_data_available(&out), 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        };

        /* Test s2n_finish_psk_extension with known values */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_stuffer_write(&conn->handshake.io, &client_hello_prefix));
            conn->psk_params.binder_list_size = full_client_hello.size - client_hello_prefix.size;
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&conn->handshake.io, conn->psk_params.binder_list_size));

            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &psk));
            EXPECT_OK(s2n_psk_init(psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_set_identity(psk, identity.data, identity.size));
            EXPECT_SUCCESS(s2n_psk_set_secret(psk, resumption_secret.data, resumption_secret.size));

            EXPECT_OK(s2n_finish_psk_extension(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->handshake.io), full_client_hello.size);
            EXPECT_BYTEARRAY_EQUAL(conn->handshake.io.blob.data, full_client_hello.data, full_client_hello.size);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_connection_append_psk */
    {
        uint8_t identity_0[] = "identity";
        uint8_t secret_0[] = "secret";

        uint8_t identity_1[] = "identity 1";

        uint8_t huge_identity[UINT16_MAX] = { 0 };

        DEFER_CLEANUP(struct s2n_psk *input_psk = s2n_external_psk_new(), s2n_psk_free);
        EXPECT_SUCCESS(s2n_psk_set_identity(input_psk, identity_0, sizeof(identity_0)));
        EXPECT_SUCCESS(s2n_psk_set_secret(input_psk, secret_0, sizeof(secret_0)));
        EXPECT_SUCCESS(s2n_psk_set_hmac(input_psk, S2N_PSK_HMAC_SHA384));

        /* Safety checks */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_append_psk(NULL, input_psk), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_append_psk(conn, NULL), S2N_ERR_NULL);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Append valid PSK to empty list */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_connection_append_psk(conn, input_psk));

            struct s2n_psk *actual_psk = NULL;
            EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void **) &actual_psk));
            EXPECT_NOT_NULL(actual_psk);

            EXPECT_EQUAL(actual_psk->type, S2N_PSK_TYPE_EXTERNAL);
            EXPECT_EQUAL(actual_psk->identity.size, input_psk->identity.size);
            EXPECT_BYTEARRAY_EQUAL(actual_psk->identity.data, input_psk->identity.data, input_psk->identity.size);
            EXPECT_EQUAL(actual_psk->secret.size, input_psk->secret.size);
            EXPECT_BYTEARRAY_EQUAL(actual_psk->secret.data, input_psk->secret.data, input_psk->secret.size);
            EXPECT_EQUAL(actual_psk->hmac_alg, S2N_HMAC_SHA384);
            EXPECT_EQUAL(actual_psk->ticket_age_add, 0);
            EXPECT_EQUAL(actual_psk->ticket_issue_time, 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Original PSK can be safely freed after being added to a connection */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_psk *original_psk = s2n_external_psk_new();
            EXPECT_SUCCESS(s2n_psk_set_identity(original_psk, identity_0, sizeof(identity_0)));
            EXPECT_SUCCESS(s2n_psk_set_secret(original_psk, secret_0, sizeof(secret_0)));
            EXPECT_SUCCESS(s2n_psk_set_hmac(original_psk, S2N_PSK_HMAC_SHA384));

            EXPECT_SUCCESS(s2n_connection_append_psk(conn, original_psk));

            /* Original PSK freed */
            EXPECT_SUCCESS(s2n_psk_free(&original_psk));
            EXPECT_NULL(original_psk);

            /* PSK on connection not freed */
            struct s2n_psk *expected_psk = NULL;
            EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void **) &expected_psk));
            EXPECT_NOT_NULL(expected_psk);

            /* PSK on connection's buffers not freed */
            EXPECT_EQUAL(expected_psk->identity.size, input_psk->identity.size);
            EXPECT_BYTEARRAY_EQUAL(expected_psk->identity.data, input_psk->identity.data, input_psk->identity.size);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Invalid PSK not added to connection */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            /* PSK is invalid because it has no identity */
            DEFER_CLEANUP(struct s2n_psk *invalid_psk = s2n_external_psk_new(), s2n_psk_free);
            EXPECT_SUCCESS(s2n_psk_set_secret(invalid_psk, secret_0, sizeof(secret_0)));

            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_append_psk(conn, invalid_psk),
                    S2N_ERR_INVALID_ARGUMENT);
            EXPECT_EQUAL(conn->psk_params.psk_list.len, 0);

            /* Successful if identity added to PSK, making it valid */
            EXPECT_SUCCESS(s2n_psk_set_identity(invalid_psk, identity_0, sizeof(identity_0)));
            EXPECT_SUCCESS(s2n_connection_append_psk(conn, invalid_psk));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Huge PSK not added to client connection */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            DEFER_CLEANUP(struct s2n_psk *invalid_psk = s2n_external_psk_new(), s2n_psk_free);
            EXPECT_SUCCESS(s2n_psk_set_secret(invalid_psk, secret_0, sizeof(secret_0)));

            /* PSK is invalid because it will not fit in the PSK extension */
            uint16_t max_identity_size = UINT16_MAX
                    - S2N_EXTENSION_HEADER_LENGTH
                    - sizeof(uint16_t)      /* identity list size */
                    - sizeof(uint16_t)      /* identity size */
                    - sizeof(uint32_t)      /* obfuscated age add */
                    - sizeof(uint16_t)      /* binder list size */
                    - sizeof(uint8_t)       /* binder size */
                    - SHA256_DIGEST_LENGTH; /* binder */
            EXPECT_SUCCESS(s2n_psk_set_identity(invalid_psk, huge_identity, max_identity_size + 1));

            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_append_psk(conn, invalid_psk),
                    S2N_ERR_OFFERED_PSKS_TOO_LONG);
            EXPECT_EQUAL(conn->psk_params.psk_list.len, 0);

            /* Successful if smaller identity used */
            EXPECT_SUCCESS(s2n_psk_set_identity(invalid_psk, huge_identity, max_identity_size));
            EXPECT_SUCCESS(s2n_connection_append_psk(conn, invalid_psk));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Huge PSK added to server connection */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            DEFER_CLEANUP(struct s2n_psk *invalid_psk = s2n_external_psk_new(), s2n_psk_free);
            EXPECT_SUCCESS(s2n_psk_set_secret(invalid_psk, secret_0, sizeof(secret_0)));
            EXPECT_EQUAL(sizeof(huge_identity), UINT16_MAX);

            EXPECT_SUCCESS(s2n_psk_set_identity(invalid_psk, huge_identity, sizeof(huge_identity)));

            EXPECT_SUCCESS(s2n_connection_append_psk(conn, invalid_psk));
            EXPECT_EQUAL(conn->psk_params.psk_list.len, 1);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* New PSK would make existing list too long for client */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            uint32_t offered_psks_size = 0;
            struct s2n_psk *test_psk = NULL;
            EXPECT_SUCCESS(s2n_connection_set_psk_mode(conn, S2N_PSK_MODE_EXTERNAL));
            while (offered_psks_size < UINT16_MAX) {
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &test_psk));
                EXPECT_NOT_NULL(test_psk);

                EXPECT_OK(s2n_psk_init(test_psk, S2N_PSK_TYPE_EXTERNAL));
                EXPECT_SUCCESS(s2n_psk_set_identity(test_psk, identity_1, sizeof(identity_1)));
                EXPECT_OK(s2n_psk_parameters_offered_psks_size(&conn->psk_params, &offered_psks_size));
            }

            /* Delete the last PSK that caused the list to exceed the allowed size */
            EXPECT_OK(s2n_psk_wipe(test_psk));
            EXPECT_OK(s2n_array_remove(&conn->psk_params.psk_list, conn->psk_params.psk_list.len - 1));
            EXPECT_OK(s2n_psk_parameters_offered_psks_size(&conn->psk_params, &offered_psks_size));
            EXPECT_TRUE(offered_psks_size < UINT16_MAX);

            uint32_t original_psk_count = conn->psk_params.psk_list.len;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_append_psk(conn, input_psk),
                    S2N_ERR_OFFERED_PSKS_TOO_LONG);
            EXPECT_EQUAL(conn->psk_params.psk_list.len, original_psk_count);

            /* Server allows an arbitrarily long list */
            conn->mode = S2N_SERVER;
            EXPECT_SUCCESS(s2n_connection_append_psk(conn, input_psk));
            EXPECT_EQUAL(conn->psk_params.psk_list.len, original_psk_count + 1);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* PSK matches existing external PSK */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_connection_append_psk(conn, input_psk));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_append_psk(conn, input_psk),
                    S2N_ERR_DUPLICATE_PSK_IDENTITIES);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Can't mix resumption and external PSKs */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);

            DEFER_CLEANUP(struct s2n_psk *test_external_psk = s2n_test_psk_new(conn), s2n_psk_free);
            test_external_psk->type = S2N_PSK_TYPE_EXTERNAL;
            DEFER_CLEANUP(struct s2n_psk *test_resumption_psk = s2n_test_psk_new(conn), s2n_psk_free);
            test_resumption_psk->type = S2N_PSK_TYPE_RESUMPTION;

            /* Add resumption to list that contains external */
            {
                EXPECT_SUCCESS(s2n_connection_append_psk(conn, test_external_psk));
                EXPECT_FAILURE_WITH_ERRNO(s2n_connection_append_psk(conn, test_resumption_psk),
                        S2N_ERR_PSK_MODE);
            };

            EXPECT_SUCCESS(s2n_connection_wipe(conn));

            /* Add external to a list that contains resumption */
            {
                EXPECT_SUCCESS(s2n_connection_append_psk(conn, test_resumption_psk));
                EXPECT_FAILURE_WITH_ERRNO(s2n_connection_append_psk(conn, test_external_psk),
                        S2N_ERR_PSK_MODE);
            };

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test: s2n_psk_set_hmac */
    {
        EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_hmac(NULL, S2N_PSK_HMAC_SHA256), S2N_ERR_NULL);

        DEFER_CLEANUP(struct s2n_psk psk, s2n_psk_wipe);
        EXPECT_OK(s2n_psk_init(&psk, S2N_PSK_TYPE_EXTERNAL));

        EXPECT_EQUAL(psk.hmac_alg, S2N_HMAC_SHA256);
        EXPECT_FAILURE_WITH_ERRNO(s2n_psk_set_hmac(&psk, -1), S2N_ERR_HMAC_INVALID_ALGORITHM);
        EXPECT_EQUAL(psk.hmac_alg, S2N_HMAC_SHA256);

        EXPECT_SUCCESS(s2n_psk_set_hmac(&psk, S2N_PSK_HMAC_SHA384));
        EXPECT_EQUAL(psk.hmac_alg, S2N_HMAC_SHA384);

        EXPECT_SUCCESS(s2n_psk_set_hmac(&psk, S2N_PSK_HMAC_SHA256));
        EXPECT_EQUAL(psk.hmac_alg, S2N_HMAC_SHA256);
    };

    /* Test: s2n_config_set_psk_mode */
    {
        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);
        EXPECT_EQUAL(config->psk_mode, S2N_PSK_MODE_RESUMPTION);

        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_psk_mode(NULL, S2N_PSK_MODE_EXTERNAL), S2N_ERR_NULL);
        EXPECT_EQUAL(config->psk_mode, S2N_PSK_MODE_RESUMPTION);

        EXPECT_SUCCESS(s2n_config_set_psk_mode(config, S2N_PSK_MODE_EXTERNAL));
        EXPECT_EQUAL(config->psk_mode, S2N_PSK_MODE_EXTERNAL);

        EXPECT_SUCCESS(s2n_config_set_psk_mode(config, S2N_PSK_MODE_RESUMPTION));
        EXPECT_EQUAL(config->psk_mode, S2N_PSK_MODE_RESUMPTION);

        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test: s2n_connection_set_psk_mode */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        EXPECT_EQUAL(conn->psk_params.type, S2N_PSK_TYPE_RESUMPTION);

        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_psk_mode(NULL, S2N_PSK_MODE_EXTERNAL), S2N_ERR_NULL);
        EXPECT_EQUAL(conn->psk_params.type, S2N_PSK_TYPE_RESUMPTION);
        EXPECT_FALSE(conn->psk_mode_overridden);

        EXPECT_SUCCESS(s2n_connection_set_psk_mode(conn, S2N_PSK_MODE_RESUMPTION));
        EXPECT_EQUAL(conn->psk_params.type, S2N_PSK_TYPE_RESUMPTION);
        EXPECT_TRUE(conn->psk_mode_overridden);

        EXPECT_SUCCESS(s2n_connection_set_psk_mode(conn, S2N_PSK_MODE_EXTERNAL));
        EXPECT_EQUAL(conn->psk_params.type, S2N_PSK_TYPE_EXTERNAL);
        EXPECT_TRUE(conn->psk_mode_overridden);

        DEFER_CLEANUP(struct s2n_psk *test_external_psk = s2n_test_psk_new(conn), s2n_psk_free);
        EXPECT_SUCCESS(s2n_connection_append_psk(conn, test_external_psk));
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_psk_mode(conn, S2N_PSK_MODE_RESUMPTION), S2N_ERR_PSK_MODE);
        EXPECT_EQUAL(conn->psk_params.type, S2N_PSK_TYPE_EXTERNAL);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: s2n_connection_get_negotiated_psk_identity_length */
    {
        const uint8_t psk_identity[] = "identity";
        struct s2n_connection *conn = NULL;
        uint16_t identity_length = 0;

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_negotiated_psk_identity_length(NULL, &identity_length), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_negotiated_psk_identity_length(conn, NULL), S2N_ERR_NULL);

        EXPECT_NULL(conn->psk_params.chosen_psk);
        EXPECT_SUCCESS(s2n_connection_get_negotiated_psk_identity_length(conn, &identity_length));
        EXPECT_EQUAL(identity_length, 0);

        DEFER_CLEANUP(struct s2n_psk *psk = s2n_external_psk_new(), s2n_psk_free);
        EXPECT_SUCCESS(s2n_psk_set_identity(psk, psk_identity, sizeof(psk_identity)));
        conn->psk_params.chosen_psk = psk;
        EXPECT_SUCCESS(s2n_connection_get_negotiated_psk_identity_length(conn, &identity_length));
        EXPECT_EQUAL(identity_length, sizeof(psk_identity));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: s2n_connection_get_negotiated_psk_identity */
    {
        const uint8_t psk_identity[] = "identity";
        const uint8_t empty_identity[sizeof(psk_identity)] = { 0 };
        struct s2n_connection *conn = NULL;
        uint8_t identity[sizeof(psk_identity)] = { 0 };
        uint16_t max_identity_length = 0;

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_negotiated_psk_identity(NULL, identity, max_identity_length), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_negotiated_psk_identity(conn, NULL, max_identity_length), S2N_ERR_NULL);

        EXPECT_NULL(conn->psk_params.chosen_psk);
        EXPECT_SUCCESS(s2n_connection_get_negotiated_psk_identity(conn, identity, max_identity_length));
        EXPECT_EQUAL(max_identity_length, 0);
        EXPECT_BYTEARRAY_EQUAL(identity, empty_identity, sizeof(empty_identity));

        DEFER_CLEANUP(struct s2n_psk *psk = s2n_external_psk_new(), s2n_psk_free);
        EXPECT_SUCCESS(s2n_psk_set_identity(psk, psk_identity, sizeof(psk_identity)));
        conn->psk_params.chosen_psk = psk;
        EXPECT_SUCCESS(s2n_connection_get_negotiated_psk_identity_length(conn, &max_identity_length));
        EXPECT_SUCCESS(s2n_connection_get_negotiated_psk_identity(conn, identity, max_identity_length));
        EXPECT_BYTEARRAY_EQUAL(identity, psk_identity, sizeof(psk_identity));

        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_negotiated_psk_identity(conn, identity, 0), S2N_ERR_INSUFFICIENT_MEM_SIZE);
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_psk_validate_keying_material */
    {
        uint64_t current_time = 100;

        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_psk_validate_keying_material(NULL), S2N_ERR_NULL);

        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);
        EXPECT_OK(s2n_config_mock_wall_clock(config, &current_time));

        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        DEFER_CLEANUP(struct s2n_psk *chosen_psk = s2n_test_psk_new(conn), s2n_psk_free);

        /* No-op if no chosen PSK */
        EXPECT_OK(s2n_psk_validate_keying_material(conn));

        conn->psk_params.chosen_psk = chosen_psk;

        /* No-op if chosen PSK is external */
        chosen_psk->type = S2N_PSK_TYPE_EXTERNAL;
        EXPECT_OK(s2n_psk_validate_keying_material(conn));

        chosen_psk->type = S2N_PSK_TYPE_RESUMPTION;

        /* Okay if chosen PSK's material is not expired */
        chosen_psk->keying_material_expiration = UINT64_MAX;
        EXPECT_OK(s2n_psk_validate_keying_material(conn));

        /* Fails if chosen PSK's material is expired */
        chosen_psk->keying_material_expiration = 0;
        EXPECT_ERROR_WITH_ERRNO(s2n_psk_validate_keying_material(conn), S2N_ERR_KEYING_MATERIAL_EXPIRED);

        /* Fails if chosen PSK's material expires at current_time */
        chosen_psk->keying_material_expiration = current_time;
        EXPECT_ERROR_WITH_ERRNO(s2n_psk_validate_keying_material(conn), S2N_ERR_KEYING_MATERIAL_EXPIRED);

        /* Fails if chosen PSK's material has less than 1s left to live */
        chosen_psk->keying_material_expiration = current_time + 1;
        EXPECT_ERROR_WITH_ERRNO(s2n_psk_validate_keying_material(conn), S2N_ERR_KEYING_MATERIAL_EXPIRED);

        /* Okay if chosen PSK's material has more than 1s left to live */
        chosen_psk->keying_material_expiration = current_time + ONE_SEC_IN_NANOS + 1;
        EXPECT_OK(s2n_psk_validate_keying_material(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    END_TEST();
}
