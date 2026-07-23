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

/* Tests for on-demand X509 materialization from the zero-copy path ().
 *
 * Verifies:
 *  - s2n_x509_validator_get_validated_cert_chain materializes STACK_OF(X509)
 *    from the validated_path DER spans when on the zero-copy path
 *  - The materialized X509 objects encode back to the same DER bytes
 *  - s2n_connection_get_peer_cert_chain serves DER directly from wire_chain
 *    on the zero-copy path without materializing X509 objects
 *  - Cleanup (owned flag) works correctly for both paths
 *
 * 
 */

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_x509_validator.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    #include "crypto/s2n_openssl_x509.h"
    #include "tls/s2n_cert_parse.h"
    #include "tls/s2n_cert_path.h"
#endif

int main(int argc, char *argv[])
{
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    /* Test: get_validated_cert_chain materializes X509 from zero-copy path */
    {
        /* Set up a trust store and perform a real handshake so we can compare
         * the libcrypto and zero-copy materialization paths. */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Perform a handshake — the libcrypto path validates the peer cert chain. */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Get the validated chain via the libcrypto path (baseline). */
        struct s2n_x509_validator *validator = &client_conn->x509_validator;
        EXPECT_TRUE(s2n_x509_validator_is_cert_chain_validated(validator));

        DEFER_CLEANUP(struct s2n_validated_cert_chain libcrypto_chain = { 0 },
                s2n_x509_validator_validated_cert_chain_free);
        EXPECT_OK(s2n_x509_validator_get_validated_cert_chain(validator, &libcrypto_chain));
        EXPECT_NOT_NULL(libcrypto_chain.stack);

        int libcrypto_cert_count = sk_X509_num(libcrypto_chain.stack);
        EXPECT_TRUE(libcrypto_cert_count > 0);

        /* Save the DER of each cert from the libcrypto chain for comparison. */
        struct s2n_blob libcrypto_ders[S2N_CERT_CHAIN_SPANS_MAX] = { { 0 } };
        for (int i = 0; i < libcrypto_cert_count && i < S2N_CERT_CHAIN_SPANS_MAX; i++) {
            X509 *cert = sk_X509_value(libcrypto_chain.stack, i);
            EXPECT_NOT_NULL(cert);
            uint8_t *data = NULL;
            int len = i2d_X509(cert, &data);
            EXPECT_TRUE(len > 0);
            libcrypto_ders[i].data = data;
            libcrypto_ders[i].size = (uint32_t) len;
        }

        /* Now simulate the zero-copy path by populating the validator's CBS
         * fields. We construct wire_chain from the libcrypto chain's DER.
         * The handshake may have already populated these fields (the zero-copy
         * backend allocates them); free them first so this block owns them. */
        EXPECT_SUCCESS(s2n_free(&validator->wire_chain));
        EXPECT_SUCCESS(s2n_free(&validator->chain_spans_mem));
        validator->chain_spans = NULL;

        uint32_t total_der_size = 0;
        for (int i = 0; i < libcrypto_cert_count && i < S2N_CERT_CHAIN_SPANS_MAX; i++) {
            total_der_size += libcrypto_ders[i].size;
        }

        EXPECT_SUCCESS(s2n_alloc(&validator->wire_chain, total_der_size));
        uint32_t offset = 0;
        for (int i = 0; i < libcrypto_cert_count && i < S2N_CERT_CHAIN_SPANS_MAX; i++) {
            memcpy(validator->wire_chain.data + offset, libcrypto_ders[i].data, libcrypto_ders[i].size);
            offset += libcrypto_ders[i].size;
        }

        /* Parse the concatenated DER into span views. */
        EXPECT_SUCCESS(s2n_alloc(&validator->chain_spans_mem, sizeof(struct s2n_cert_chain_spans)));
        validator->chain_spans = (struct s2n_cert_chain_spans *) (void *) validator->chain_spans_mem.data;
        *validator->chain_spans = (struct s2n_cert_chain_spans){ 0 };
        EXPECT_OK(s2n_cert_chain_spans_parse(validator->chain_spans,
                &validator->wire_chain, validator->max_chain_depth));
        EXPECT_TRUE(validator->chain_spans->count > 0);
        EXPECT_EQUAL(validator->chain_spans->count, (uint32_t) libcrypto_cert_count);

        /* Build a validated_path that mirrors the libcrypto validated chain:
         * all entries point to wire certs in order. (In a real zero-copy
         * validation, the last entry might be an anchor, but for this test we
         * just validate the materialization from wire certs.) */
        validator->validated_path.count = validator->chain_spans->count;
        for (uint32_t i = 0; i < validator->chain_spans->count; i++) {
            validator->validated_path.entries[i].type = S2N_CERT_PATH_ENTRY_WIRE;
            validator->validated_path.entries[i].entry_index = i;
        }

        /* Call get_validated_cert_chain — it should take the zero-copy
         * materialization path (wire_chain.data != NULL). */
        DEFER_CLEANUP(struct s2n_validated_cert_chain zc_chain = { 0 },
                s2n_x509_validator_validated_cert_chain_free);
        EXPECT_OK(s2n_x509_validator_get_validated_cert_chain(validator, &zc_chain));
        EXPECT_NOT_NULL(zc_chain.stack);
        EXPECT_TRUE(zc_chain.owned);

        int zc_cert_count = sk_X509_num(zc_chain.stack);
        EXPECT_EQUAL(zc_cert_count, libcrypto_cert_count);

        /* Verify that the materialized X509 objects encode to the same DER as
         * the original libcrypto chain. */
        for (int i = 0; i < zc_cert_count; i++) {
            X509 *cert = sk_X509_value(zc_chain.stack, i);
            EXPECT_NOT_NULL(cert);
            uint8_t *data = NULL;
            int len = i2d_X509(cert, &data);
            EXPECT_TRUE(len > 0);
            EXPECT_EQUAL((uint32_t) len, libcrypto_ders[i].size);
            EXPECT_BYTEARRAY_EQUAL(data, libcrypto_ders[i].data, len);
            OPENSSL_free(data);
        }

        /* Cleanup: free the DER blobs we saved for comparison. */
        for (int i = 0; i < libcrypto_cert_count && i < S2N_CERT_CHAIN_SPANS_MAX; i++) {
            OPENSSL_free(libcrypto_ders[i].data);
            libcrypto_ders[i].data = NULL;
        }

        /* Clean up the wire_chain we manually allocated. The validator wipe
         * will free it, but we need to clear our path to avoid double-free
         * issues with the store_ctx path that was also populated. */
        EXPECT_SUCCESS(s2n_free(&validator->wire_chain));
        EXPECT_SUCCESS(s2n_free(&validator->chain_spans_mem));
        validator->chain_spans = NULL;
        validator->validated_path = (struct s2n_cert_path){ 0 };
    }

    /* Test: s2n_connection_get_peer_cert_chain serves DER directly on zero-copy path */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Handshake to get a validated chain. */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        struct s2n_x509_validator *validator = &client_conn->x509_validator;
        EXPECT_TRUE(s2n_x509_validator_is_cert_chain_validated(validator));

        /* Get the peer cert chain via the libcrypto path (baseline). */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *peer_chain_libcrypto = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_NOT_NULL(peer_chain_libcrypto);
        EXPECT_SUCCESS(s2n_connection_get_peer_cert_chain(client_conn, peer_chain_libcrypto));

        /* Count certs and save DER from the libcrypto path. */
        uint32_t libcrypto_count = 0;
        EXPECT_SUCCESS(s2n_cert_chain_get_length(peer_chain_libcrypto, &libcrypto_count));
        EXPECT_TRUE(libcrypto_count > 0);

        /* Now simulate the zero-copy path: populate wire_chain + chain_spans +
         * validated_path from the existing validated chain. */
        DEFER_CLEANUP(struct s2n_validated_cert_chain existing_chain = { 0 },
                s2n_x509_validator_validated_cert_chain_free);
        EXPECT_OK(s2n_x509_validator_get_validated_cert_chain(validator, &existing_chain));

        int cert_count = sk_X509_num(existing_chain.stack);
        EXPECT_TRUE(cert_count > 0);

        /* Build the wire_chain from the existing validated certs' DER. The
         * handshake may have already populated the CBS fields (the zero-copy
         * backend allocates them); free them first so this block owns them. */
        EXPECT_SUCCESS(s2n_free(&validator->wire_chain));
        EXPECT_SUCCESS(s2n_free(&validator->chain_spans_mem));
        validator->chain_spans = NULL;

        uint32_t total_size = 0;
        for (int i = 0; i < cert_count; i++) {
            total_size += (uint32_t) i2d_X509(sk_X509_value(existing_chain.stack, i), NULL);
        }

        EXPECT_SUCCESS(s2n_alloc(&validator->wire_chain, total_size));
        uint32_t write_offset = 0;
        for (int i = 0; i < cert_count; i++) {
            uint8_t *ptr = validator->wire_chain.data + write_offset;
            int len = i2d_X509(sk_X509_value(existing_chain.stack, i), &ptr);
            EXPECT_TRUE(len > 0);
            write_offset += (uint32_t) len;
        }

        /* Parse span views. */
        EXPECT_SUCCESS(s2n_alloc(&validator->chain_spans_mem, sizeof(struct s2n_cert_chain_spans)));
        validator->chain_spans = (struct s2n_cert_chain_spans *) (void *) validator->chain_spans_mem.data;
        *validator->chain_spans = (struct s2n_cert_chain_spans){ 0 };
        EXPECT_OK(s2n_cert_chain_spans_parse(validator->chain_spans,
                &validator->wire_chain, validator->max_chain_depth));
        EXPECT_EQUAL(validator->chain_spans->count, (uint32_t) cert_count);

        /* Set up the validated path. */
        validator->validated_path.count = validator->chain_spans->count;
        for (uint32_t i = 0; i < validator->chain_spans->count; i++) {
            validator->validated_path.entries[i].type = S2N_CERT_PATH_ENTRY_WIRE;
            validator->validated_path.entries[i].entry_index = i;
        }

        /* Now call s2n_connection_get_peer_cert_chain — this should use the
         * zero-copy fast path (serving DER directly from wire_chain). */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *peer_chain_zc = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_NOT_NULL(peer_chain_zc);
        EXPECT_SUCCESS(s2n_connection_get_peer_cert_chain(client_conn, peer_chain_zc));

        /* Verify the zero-copy peer chain matches the libcrypto peer chain. */
        uint32_t zc_count = 0;
        EXPECT_SUCCESS(s2n_cert_chain_get_length(peer_chain_zc, &zc_count));
        EXPECT_EQUAL(zc_count, libcrypto_count);

        /* Compare each cert's DER between the two chains. */
        struct s2n_cert *libcrypto_node = peer_chain_libcrypto->cert_chain->head;
        struct s2n_cert *zc_node = peer_chain_zc->cert_chain->head;
        for (uint32_t i = 0; i < zc_count; i++) {
            EXPECT_NOT_NULL(libcrypto_node);
            EXPECT_NOT_NULL(zc_node);
            EXPECT_EQUAL(zc_node->raw.size, libcrypto_node->raw.size);
            EXPECT_BYTEARRAY_EQUAL(zc_node->raw.data, libcrypto_node->raw.data, zc_node->raw.size);
            libcrypto_node = libcrypto_node->next;
            zc_node = zc_node->next;
        }
        EXPECT_NULL(libcrypto_node);
        EXPECT_NULL(zc_node);

        /* Cleanup the manually-allocated wire chain. */
        EXPECT_SUCCESS(s2n_free(&validator->wire_chain));
        EXPECT_SUCCESS(s2n_free(&validator->chain_spans_mem));
        validator->chain_spans = NULL;
        validator->validated_path = (struct s2n_cert_path){ 0 };
    }

    /* Test: validated_cert_chain cleanup properly frees owned stacks */
    {
        /* Owned stack should be freed. */
        {
            struct s2n_validated_cert_chain chain = { 0 };
            chain.stack = sk_X509_new_null();
            EXPECT_NOT_NULL(chain.stack);
            chain.owned = true;
            EXPECT_OK(s2n_x509_validator_validated_cert_chain_free(&chain));
            EXPECT_NULL(chain.stack);
        }

        /* Non-owned stack should NOT be freed (just nulled). */
        {
            STACK_OF(X509) *external_stack = sk_X509_new_null();
            EXPECT_NOT_NULL(external_stack);

            struct s2n_validated_cert_chain chain = { 0 };
            chain.stack = external_stack;
            chain.owned = false;
            EXPECT_OK(s2n_x509_validator_validated_cert_chain_free(&chain));
            EXPECT_NULL(chain.stack);

            /* external_stack is still valid (not freed) — clean it up. */
            sk_X509_free(external_stack);
        }
    }

    /* Test: get_validated_cert_chain fails with INVALID_CERT_STATE when no
     * chain has been validated (neither libcrypto nor zero-copy). */
    {
        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init_no_x509_validation(&validator));

        struct s2n_validated_cert_chain chain = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_get_validated_cert_chain(&validator, &chain),
                S2N_ERR_INVALID_CERT_STATE);
        EXPECT_NULL(chain.stack);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    }
#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
