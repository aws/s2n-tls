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
        DEFER_CLEANUP(struct s2n_psk psk, s2n_psk_free);

        EXPECT_SUCCESS(s2n_psk_init(&psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_EQUAL(psk.type, S2N_PSK_TYPE_EXTERNAL);
        EXPECT_EQUAL(psk.hmac_alg, S2N_HMAC_SHA256);
        EXPECT_EQUAL(psk.obfuscated_ticket_age, 0);

        EXPECT_SUCCESS(s2n_psk_init(&psk, S2N_PSK_TYPE_RESUMPTION));
        EXPECT_EQUAL(psk.type, S2N_PSK_TYPE_RESUMPTION);
        EXPECT_EQUAL(psk.hmac_alg, S2N_HMAC_SHA256);
        EXPECT_EQUAL(psk.obfuscated_ticket_age, 0);
    }

    /* Test s2n_psk_new_identity */
    {
        DEFER_CLEANUP(struct s2n_psk psk, s2n_psk_free);
        EXPECT_SUCCESS(s2n_psk_init(&psk, S2N_PSK_TYPE_EXTERNAL));

        uint8_t test_value_1[] = TEST_VALUE_1;

        EXPECT_SUCCESS(s2n_psk_new_identity(&psk, test_value_1, sizeof(test_value_1)));
        EXPECT_EQUAL(psk.identity.size, sizeof(TEST_VALUE_1));
        EXPECT_BYTEARRAY_EQUAL(psk.identity.data, TEST_VALUE_1, sizeof(TEST_VALUE_1));

        /* source can be modified without affecting psk */
        test_value_1[0] = 'A';
        EXPECT_BYTEARRAY_EQUAL(psk.identity.data, TEST_VALUE_1, sizeof(TEST_VALUE_1));

        /* method can be called again to replace identity */
        uint8_t test_value_2[] = TEST_VALUE_2;
        EXPECT_SUCCESS(s2n_psk_new_identity(&psk, test_value_2, sizeof(test_value_2)));
        EXPECT_EQUAL(psk.identity.size, sizeof(TEST_VALUE_2));
        EXPECT_BYTEARRAY_EQUAL(psk.identity.data, TEST_VALUE_2, sizeof(TEST_VALUE_2));
    }

    /* Test s2n_psk_new_secret */
    {
        DEFER_CLEANUP(struct s2n_psk psk, s2n_psk_free);
        EXPECT_SUCCESS(s2n_psk_init(&psk, S2N_PSK_TYPE_EXTERNAL));

        uint8_t test_value_1[] = TEST_VALUE_1;

        EXPECT_SUCCESS(s2n_psk_new_secret(&psk, test_value_1, sizeof(test_value_1)));
        EXPECT_EQUAL(psk.secret.size, sizeof(TEST_VALUE_1));
        EXPECT_BYTEARRAY_EQUAL(psk.secret.data, TEST_VALUE_1, sizeof(TEST_VALUE_1));

        /* source identity can be modified without affecting psk */
        test_value_1[0] = 'A';
        EXPECT_BYTEARRAY_EQUAL(psk.secret.data, TEST_VALUE_1, sizeof(TEST_VALUE_1));

        /* method can be called again to replace secret */
        uint8_t test_value_2[] = TEST_VALUE_2;
        EXPECT_SUCCESS(s2n_psk_new_secret(&psk, test_value_2, sizeof(test_value_2)));
        EXPECT_EQUAL(psk.secret.size, sizeof(TEST_VALUE_2));
        EXPECT_BYTEARRAY_EQUAL(psk.secret.data, TEST_VALUE_2, sizeof(TEST_VALUE_2));
    }

    /* Test s2n_psk_free */
    {
        const uint8_t test_value[] = TEST_VALUE_1;
        struct s2n_psk psk;
        EXPECT_SUCCESS(s2n_psk_init(&psk, S2N_PSK_TYPE_EXTERNAL));

        /* No-op if blobs not allocated yet */
        EXPECT_SUCCESS(s2n_psk_free(&psk));

        EXPECT_SUCCESS(s2n_psk_new_identity(&psk, test_value, sizeof(test_value)));
        EXPECT_NOT_EQUAL(psk.identity.size, 0);
        EXPECT_SUCCESS(s2n_psk_new_secret(&psk, test_value, sizeof(test_value)));
        EXPECT_NOT_EQUAL(psk.secret.size, 0);
        EXPECT_SUCCESS(s2n_alloc(&psk.early_secret, sizeof(test_value)));
        EXPECT_NOT_EQUAL(psk.early_secret.size, 0);

        /* Frees all blobs */
        EXPECT_SUCCESS(s2n_psk_free(&psk));
        EXPECT_EQUAL(psk.identity.data, NULL);
        EXPECT_EQUAL(psk.identity.size, 0);
        EXPECT_EQUAL(psk.secret.data, NULL);
        EXPECT_EQUAL(psk.secret.size, 0);
        EXPECT_EQUAL(psk.early_secret.data, NULL);
        EXPECT_EQUAL(psk.early_secret.size, 0);

        /* No-op if already freed */
        EXPECT_SUCCESS(s2n_psk_free(&psk));
    }

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
    }

    /* Test s2n_psk_parameters_wipe */
    {
        uint8_t test_value[] = TEST_VALUE_1;

        DEFER_CLEANUP(struct s2n_psk_parameters params = { 0 }, s2n_psk_parameters_wipe);
        EXPECT_OK(s2n_psk_parameters_init(&params));
        params.binder_list_size = 1;
        params.chosen_psk_wire_index = 1;

        struct s2n_psk *chosen_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&params.psk_list, (void**) &chosen_psk));
        EXPECT_SUCCESS(s2n_psk_init(chosen_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_new_identity(chosen_psk, test_value, sizeof(test_value)));
        params.chosen_psk = chosen_psk;

        struct s2n_psk *other_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&params.psk_list, (void**) &other_psk));
        EXPECT_SUCCESS(s2n_psk_init(other_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_new_identity(other_psk, test_value, sizeof(test_value)));

        EXPECT_ERROR_WITH_ERRNO(s2n_psk_parameters_wipe(NULL), S2N_ERR_NULL);
        EXPECT_OK(s2n_psk_parameters_wipe(&params));

        /* Verify params are wiped.
         * The params should be back to their initial state. */
        struct s2n_psk_parameters expected_params = { 0 };
        EXPECT_OK(s2n_psk_parameters_init(&expected_params));
        EXPECT_BYTEARRAY_EQUAL(&expected_params, &params, sizeof(struct s2n_psk_parameters));
    }

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
        EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &first_psk));
        EXPECT_SUCCESS(s2n_psk_init(first_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_new_identity(first_psk, test_value, sizeof(test_value)));
        conn->psk_params.chosen_psk = first_psk;

        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        EXPECT_BYTEARRAY_EQUAL(&empty_psk_params, &conn->psk_params, sizeof(struct s2n_psk_parameters));

        struct s2n_psk *second_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &second_psk));
        EXPECT_SUCCESS(s2n_psk_init(second_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_new_identity(second_psk, test_value, sizeof(test_value)));
        conn->psk_params.chosen_psk = second_psk;

        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        EXPECT_BYTEARRAY_EQUAL(&empty_psk_params, &conn->psk_params, sizeof(struct s2n_psk_parameters));

        struct s2n_psk *third_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &third_psk));
        EXPECT_SUCCESS(s2n_psk_init(third_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_new_identity(third_psk, test_value, sizeof(test_value)));
        conn->psk_params.chosen_psk = third_psk;

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

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
            EXPECT_OK(s2n_array_pushback(&params->psk_list, (void**) &first_psk));
            EXPECT_SUCCESS(s2n_psk_init(first_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_secret(first_psk, test_value, sizeof(test_value)));

            struct s2n_psk *second_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&params->psk_list, (void**) &second_psk));
            EXPECT_SUCCESS(s2n_psk_init(second_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_secret(second_psk, test_value, sizeof(test_value)));

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
        }

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
            conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_psk_parameters *params = &conn->psk_params;

            struct s2n_psk *other_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&params->psk_list, (void**) &other_psk));
            EXPECT_SUCCESS(s2n_psk_init(other_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_secret(other_psk, test_value, sizeof(test_value)));
            other_psk->hmac_alg = conn->secure.cipher_suite->prf_alg - 1;

            struct s2n_psk *matching_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&params->psk_list, (void**) &matching_psk));
            EXPECT_SUCCESS(s2n_psk_init(matching_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_secret(matching_psk, test_value, sizeof(test_value)));
            matching_psk->hmac_alg = conn->secure.cipher_suite->prf_alg;

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
    }

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

            struct s2n_blob hash_value;
            uint8_t hash_value_data[SHA256_DIGEST_LENGTH];
            EXPECT_SUCCESS(s2n_blob_init(&hash_value, hash_value_data, sizeof(hash_value_data)));

            EXPECT_SUCCESS(s2n_psk_calculate_binder_hash(conn, S2N_HMAC_SHA256, &client_hello_prefix, &hash_value));
            S2N_BLOB_EXPECT_EQUAL(hash_value, binder_hash);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test s2n_psk_calculate_binder with known values */
        {
            DEFER_CLEANUP(struct s2n_psk test_psk, s2n_psk_free);
            EXPECT_SUCCESS(s2n_psk_init(&test_psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_new_secret(&test_psk, resumption_secret.data, resumption_secret.size));

            struct s2n_blob binder_value;
            uint8_t binder_value_data[SHA256_DIGEST_LENGTH];
            EXPECT_SUCCESS(s2n_blob_init(&binder_value, binder_value_data, sizeof(binder_value_data)));

            EXPECT_SUCCESS(s2n_psk_calculate_binder(&test_psk, &binder_hash, &binder_value));
            S2N_BLOB_EXPECT_EQUAL(test_psk.early_secret, early_secret);
            S2N_BLOB_EXPECT_EQUAL(binder_value, finished_binder);
        }

        /* Test s2n_psk_verify_binder with known values */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            DEFER_CLEANUP(struct s2n_psk test_psk, s2n_psk_free);
            EXPECT_SUCCESS(s2n_psk_init(&test_psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_new_secret(&test_psk, resumption_secret.data, resumption_secret.size));

            struct s2n_blob binder_value;
            uint8_t binder_value_data[SHA256_DIGEST_LENGTH];
            EXPECT_SUCCESS(s2n_blob_init(&binder_value, binder_value_data, sizeof(binder_value_data)));

            EXPECT_SUCCESS(s2n_psk_verify_binder(conn, &test_psk, &client_hello_prefix, &finished_binder));
            S2N_BLOB_EXPECT_EQUAL(test_psk.early_secret, early_secret);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test s2n_psk_verify_binder with incorrect binder */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            DEFER_CLEANUP(struct s2n_psk test_psk, s2n_psk_free);
            EXPECT_SUCCESS(s2n_psk_init(&test_psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_new_secret(&test_psk, resumption_secret.data, resumption_secret.size));

            struct s2n_blob *incorrect_binder_value = &resumption_secret;

            struct s2n_blob binder_value;
            uint8_t binder_value_data[SHA256_DIGEST_LENGTH];
            EXPECT_SUCCESS(s2n_blob_init(&binder_value, binder_value_data, sizeof(binder_value_data)));

            EXPECT_FAILURE(s2n_psk_verify_binder(conn, &test_psk, &client_hello_prefix, incorrect_binder_value));
            S2N_BLOB_EXPECT_EQUAL(test_psk.early_secret, early_secret);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test s2n_psk_write_binder with known values */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            DEFER_CLEANUP(struct s2n_psk psk = { 0 }, s2n_psk_free);
            EXPECT_SUCCESS(s2n_psk_init(&psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_new_secret(&psk, resumption_secret.data, resumption_secret.size));

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
        }

        /* Test s2n_psk_write_binder_list with known values */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
            EXPECT_SUCCESS(s2n_psk_init(psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_new_identity(psk, identity.data, identity.size));
            EXPECT_SUCCESS(s2n_psk_new_secret(psk, resumption_secret.data, resumption_secret.size));

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
        }

        /* Test s2n_psk_write_binder_list with multiple PSKs */
        {
            const uint8_t psk_count = 5;

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            for (uint8_t i = 0; i < psk_count; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
                EXPECT_SUCCESS(s2n_psk_init(psk, S2N_PSK_TYPE_RESUMPTION));
                EXPECT_SUCCESS(s2n_psk_new_identity(psk, identity.data, identity.size));
                EXPECT_SUCCESS(s2n_psk_new_secret(psk, resumption_secret.data, resumption_secret.size));
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
        }

        /* Test s2n_psk_write_binder_list with multiple hash algs */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            for (s2n_hmac_algorithm hmac_alg = S2N_HMAC_SHA1; hmac_alg <= S2N_HMAC_SHA384; hmac_alg++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
                EXPECT_SUCCESS(s2n_psk_init(psk, S2N_PSK_TYPE_RESUMPTION));
                EXPECT_SUCCESS(s2n_psk_new_identity(psk, identity.data, identity.size));
                EXPECT_SUCCESS(s2n_psk_new_secret(psk, resumption_secret.data, resumption_secret.size));
                psk->hmac_alg = hmac_alg;
            }

            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            EXPECT_OK(s2n_psk_write_binder_list(conn, &client_hello_prefix, &out));

            uint16_t binder_list_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &binder_list_size));
            EXPECT_EQUAL(binder_list_size, s2n_stuffer_data_available(&out));

            for (s2n_hmac_algorithm hmac_alg = S2N_HMAC_SHA1; hmac_alg <= S2N_HMAC_SHA384; hmac_alg++) {
                uint8_t hash_size = 0;
                GUARD(s2n_hmac_digest_size(hmac_alg, &hash_size));

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
        }

        /* Test s2n_finish_psk_extension with known values */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_stuffer_write(&conn->handshake.io, &client_hello_prefix));
            conn->psk_params.binder_list_size = full_client_hello.size - client_hello_prefix.size;
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&conn->handshake.io, conn->psk_params.binder_list_size));

            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
            EXPECT_SUCCESS(s2n_psk_init(psk, S2N_PSK_TYPE_RESUMPTION));
            EXPECT_SUCCESS(s2n_psk_new_identity(psk, identity.data, identity.size));
            EXPECT_SUCCESS(s2n_psk_new_secret(psk, resumption_secret.data, resumption_secret.size));

            EXPECT_OK(s2n_finish_psk_extension(conn));
            EXPECT_EQUAL(s2n_stuffer_data_available(&conn->handshake.io), full_client_hello.size);
            EXPECT_BYTEARRAY_EQUAL(conn->handshake.io.blob.data, full_client_hello.data, full_client_hello.size);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test s2n_connection_set_external_psks */
        {
            uint8_t identity_0[] = "identity";
            uint8_t secret_0[] = "secret";

            uint8_t identity_1[] = "identity 1";
            uint8_t secret_1[] = "secret 1";

            struct s2n_external_psk first_psk = { identity_0, sizeof(identity_0), secret_0, sizeof(secret_0), S2N_PSK_HMAC_SHA384 };
            struct s2n_external_psk second_psk = { identity_1, sizeof(identity_1), secret_1, sizeof(secret_1), S2N_PSK_HMAC_SHA384 };

            /* Safety checks */
            {
                EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_external_psks(NULL, &first_psk, 1), S2N_ERR_NULL);

                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_external_psks(conn, NULL, 1), S2N_ERR_NULL);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }

            /* One psk */
            {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                size_t num_psks = 1;

                EXPECT_SUCCESS(s2n_connection_set_external_psks(conn, &first_psk, num_psks));
                
                struct s2n_psk *test_psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void**) &test_psk));
                EXPECT_NOT_NULL(test_psk);

                EXPECT_EQUAL(test_psk->type, S2N_PSK_TYPE_EXTERNAL);
                EXPECT_EQUAL(test_psk->identity.size, first_psk.identity_length);
                EXPECT_BYTEARRAY_EQUAL(test_psk->identity.data, first_psk.identity, first_psk.identity_length);
                EXPECT_EQUAL(test_psk->secret.size, first_psk.secret_length);
                EXPECT_BYTEARRAY_EQUAL(test_psk->secret.data, first_psk.secret, first_psk.secret_length);
                EXPECT_EQUAL(test_psk->hmac_alg, S2N_HMAC_SHA384);
                EXPECT_EQUAL(test_psk->obfuscated_ticket_age, 0);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }

            /* List of psks */
            {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                size_t num_psks = 2;
                struct s2n_external_psk psks[2] = { first_psk, second_psk };

                EXPECT_SUCCESS(s2n_connection_set_external_psks(conn, psks, num_psks));

                for (size_t i = 0; i < num_psks; i++) {
                    struct s2n_psk *test_psk = NULL;
                    EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, i, (void**) &test_psk));
                    EXPECT_NOT_NULL(test_psk);

                    EXPECT_EQUAL(test_psk->type, S2N_PSK_TYPE_EXTERNAL);
                    EXPECT_EQUAL(test_psk->identity.size, psks[i].identity_length);
                    EXPECT_BYTEARRAY_EQUAL(test_psk->identity.data, psks[i].identity, psks[i].identity_length);
                    EXPECT_EQUAL(test_psk->secret.size, psks[i].secret_length);
                    EXPECT_BYTEARRAY_EQUAL(test_psk->secret.data, psks[i].secret, psks[i].secret_length);
                    EXPECT_EQUAL(test_psk->hmac_alg, S2N_HMAC_SHA384);
                    EXPECT_EQUAL(test_psk->obfuscated_ticket_age, 0);
                }

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }

            /* List of psks but the last psk contains the same identity as a previous psk */
            {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                size_t num_psks = 3;
                struct s2n_external_psk psks[3] = { first_psk, second_psk, first_psk };

                EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_external_psks(conn, psks, num_psks), S2N_ERR_DUPLICATE_PSK_IDENTITIES);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }

            /* Ensures existing external psks are deleted and existing resumption psks are not deleted */
            {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

                /* Add previously set external and resumption psks */
                struct s2n_psk *external_psk = NULL;
                uint8_t external_identity[] = "external identity";
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &external_psk));
                EXPECT_SUCCESS(s2n_psk_init(external_psk, S2N_PSK_TYPE_EXTERNAL));
                EXPECT_SUCCESS(s2n_psk_new_identity(external_psk, external_identity, sizeof(external_identity)));

                struct s2n_psk *resumption_psk = NULL;
                uint8_t resumption_identity[] = "resumption identity";
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &resumption_psk));
                EXPECT_SUCCESS(s2n_psk_init(resumption_psk, S2N_PSK_TYPE_RESUMPTION));
                EXPECT_SUCCESS(s2n_psk_new_identity(resumption_psk, resumption_identity, sizeof(resumption_identity)));

                size_t num_psks = 2;
                struct s2n_external_psk psks[2] = { first_psk, second_psk };

                EXPECT_SUCCESS(s2n_connection_set_external_psks(conn, psks, num_psks));

                /* The list should now contain one resumption psk and two new external psks */
                EXPECT_EQUAL(conn->psk_params.psk_list.len, num_psks + 1);

                /* Check resumption psk was not deleted */
                struct s2n_psk *test_psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void**) &test_psk));
                EXPECT_NOT_NULL(test_psk);
                EXPECT_EQUAL(test_psk->type, S2N_PSK_TYPE_RESUMPTION);
                EXPECT_EQUAL(test_psk->identity.size, sizeof(resumption_identity));
                EXPECT_BYTEARRAY_EQUAL(test_psk->identity.data, resumption_identity, sizeof(resumption_identity));

                /* Check previously-set external psk is deleted and newest psks have been set */
                test_psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 1, (void**) &test_psk));
                EXPECT_NOT_NULL(test_psk);
                EXPECT_EQUAL(test_psk->type, S2N_PSK_TYPE_EXTERNAL);
                EXPECT_EQUAL(test_psk->identity.size, first_psk.identity_length);
                EXPECT_BYTEARRAY_EQUAL(test_psk->identity.data, first_psk.identity, first_psk.identity_length);

                test_psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 2, (void**) &test_psk));
                EXPECT_NOT_NULL(test_psk);
                EXPECT_EQUAL(test_psk->type, S2N_PSK_TYPE_EXTERNAL);
                EXPECT_EQUAL(test_psk->identity.size, second_psk.identity_length);
                EXPECT_BYTEARRAY_EQUAL(test_psk->identity.data, second_psk.identity, second_psk.identity_length);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }
        }
    }

    /* Test: s2n_psk_set_hmac */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_psk *psk = NULL;
        EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &psk));
        uint8_t test_identity[] = "test identity";
        EXPECT_SUCCESS(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_new_identity(psk, test_identity, sizeof(test_identity)));

        s2n_psk_hmac psk_hmac_alg = -1;

        EXPECT_ERROR_WITH_ERRNO(s2n_psk_set_hmac(psk, psk_hmac_alg), S2N_ERR_HMAC_INVALID_ALGORITHM);

        psk_hmac_alg = S2N_PSK_HMAC_SHA224;
        EXPECT_OK(s2n_psk_set_hmac(psk, psk_hmac_alg));
        EXPECT_EQUAL(psk->hmac_alg, S2N_HMAC_SHA224);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
}
