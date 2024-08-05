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

#include <stdint.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_kex.h"
#include "utils/s2n_random.h"

DEFINE_POINTER_CLEANUP_FUNC(struct s2n_async_pkey_op *, s2n_async_pkey_op_free);

struct s2n_test_rsa_client_key_send_ctx {
    bool override_premaster_secret_size;
    uint32_t size;

    bool invalidate_padded_premaster_secret;
    uint32_t invalidate_index;

    bool override_premaster_secret_version;
    uint8_t version;
};

static S2N_RESULT s2n_test_rsa_pkcs1_v15_padding_encrypt(struct s2n_connection *conn, struct s2n_blob *in,
        struct s2n_blob *out)
{
    /* RSAES-PKCS1-V1_5-ENCRYPT ((n, e), M) from https://www.rfc-editor.org/rfc/rfc8017#section-7.2.1 */

    /* Input:
     *    (n, e)   recipient's RSA public key (k denotes the length in
     *             octets of the modulus n)
     */
    const s2n_rsa_public_key *n_e = &conn->handshake_params.server_public_key.key.rsa_key;
    const int k = RSA_size(n_e->rsa);
    RESULT_ENSURE_GT(k, 0);

    /*    M        message to be encrypted, an octet string of length
     *             mLen, where mLen <= k - 11
     */
    struct s2n_blob *M = in;
    uint32_t mLen = M->size;

    /* Output:
     *    C        ciphertext, an octet string of length k
     */
    struct s2n_blob *C = out;
    RESULT_ENSURE_GTE(C->size, k);

    /* Steps:
    *     1.  Length checking: If mLen > k - 11, output "message too long"
    *         and stop.
    */
    RESULT_ENSURE_LTE(mLen, k - 11);

    /*   2.  EME-PKCS1-v1_5 encoding:
     *       a.  Generate an octet string PS of length k - mLen - 3
     *           consisting of pseudo-randomly generated nonzero octets.
     *           The length of PS will be at least eight octets.
     *       b.  Concatenate PS, the message M, and other padding to form
     *           an encoded message EM of length k octets as
     *              EM = 0x00 || 0x02 || PS || 0x00 || M.
     */
    uint8_t EM_data[4096] = { 0 };
    struct s2n_blob EM_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&EM_blob, EM_data, sizeof(EM_data)));
    struct s2n_stuffer EM_stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&EM_stuffer, &EM_blob));

    /* 0x00 || 0x02 */
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&EM_stuffer, 0x00));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&EM_stuffer, 0x02));

    /* || PS */
    struct s2n_blob PS_blob = { 0 };
    uint32_t PS_len = k - mLen - 3;
    uint8_t *PS_data = s2n_stuffer_raw_write(&EM_stuffer, PS_len);
    RESULT_ENSURE_REF(PS_data);
    RESULT_GUARD_POSIX(s2n_blob_init(&PS_blob, PS_data, PS_len));
    RESULT_GUARD(s2n_get_public_random_data(&PS_blob));

    /* Ensure random bytes are nonzero */
    for (size_t i = 0; i < PS_len; i++) {
        PS_data[i] = (PS_data[i] % (UINT8_MAX - 1)) + 1;
    }

    /* || 0x00 */
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&EM_stuffer, 0x00));

    /* || M */
    RESULT_GUARD_POSIX(s2n_stuffer_write(&EM_stuffer, M));

    uint8_t *EM = s2n_stuffer_raw_read(&EM_stuffer, k);
    RESULT_ENSURE_REF(EM);
    RESULT_ENSURE_EQ(s2n_stuffer_data_available(&EM_stuffer), 0);

    struct s2n_test_rsa_client_key_send_ctx *ctx = s2n_connection_get_ctx(conn);
    RESULT_ENSURE_REF(ctx);
    if (ctx->invalidate_padded_premaster_secret) {
        RESULT_ENSURE_LT(ctx->invalidate_index, k);
        if (ctx->invalidate_index > 1 && ctx->invalidate_index < 2 + PS_len) {
            /* PS bytes must not be 0. */
            EM[ctx->invalidate_index] = 0;
        } else {
            /* Otherwise bytes can be invalidated by modifying them arbitrarily. */
            EM[ctx->invalidate_index] += 1;
        }
    }

    /*   3.  RSA encryption:
     *       b.  Apply the RSAEP encryption primitive (Section 5.1.1) to
     *        the RSA public key (n, e) and the message representative m
     *        to produce an integer ciphertext representative c:
     *           c = RSAEP ((n, e), m).
     */
    int r = RSA_public_encrypt(k, (unsigned char *) EM, (unsigned char *) C->data,
            s2n_unsafe_rsa_get_non_const(n_e), RSA_NO_PADDING);
    RESULT_ENSURE((int64_t) r == (int64_t) C->size, S2N_ERR_SIZE_MISMATCH);

    return S2N_RESULT_OK;
}

/* More general version of s2n_rsa_client_key_send() that allows the premaster secret to be
 * invalidated by configuring a s2n_test_rsa_client_key_send_ctx on the connection.
 */
static int s2n_test_rsa_client_key_send(struct s2n_connection *conn, struct s2n_blob *shared_key)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(shared_key);

    struct s2n_test_rsa_client_key_send_ctx *ctx = s2n_connection_get_ctx(conn);
    POSIX_ENSURE_REF(ctx);

    uint8_t client_hello_version = s2n_connection_get_client_hello_version(conn);
    if (ctx->override_premaster_secret_version) {
        client_hello_version = ctx->version;
    }
    uint8_t client_hello_protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN];
    client_hello_protocol_version[0] = client_hello_version / 10;
    client_hello_protocol_version[1] = client_hello_version % 10;

    shared_key->data = conn->secrets.version.tls12.rsa_premaster_secret;
    uint32_t secret_size = S2N_TLS_SECRET_LEN;
    if (ctx->override_premaster_secret_size) {
        secret_size = ctx->size;
    }
    POSIX_ENSURE_LTE(secret_size, sizeof(conn->secrets.version.tls12.rsa_premaster_secret));
    shared_key->size = secret_size;

    POSIX_GUARD_RESULT(s2n_get_private_random_data(shared_key));

    /* The first two bytes of the premaster secret contain the client hello version. */
    POSIX_CHECKED_MEMCPY(conn->secrets.version.tls12.rsa_premaster_secret, client_hello_protocol_version,
            S2N_TLS_PROTOCOL_VERSION_LEN);

    uint32_t encrypted_size = 0;
    POSIX_GUARD_RESULT(s2n_pkey_size(&conn->handshake_params.server_public_key, &encrypted_size));
    POSIX_ENSURE_LTE(encrypted_size, 0xffff);

    /* Write the length. */
    POSIX_GUARD(s2n_stuffer_write_uint16(&conn->handshake.io, encrypted_size));

    struct s2n_blob encrypted = { 0 };
    encrypted.data = s2n_stuffer_raw_write(&conn->handshake.io, encrypted_size);
    encrypted.size = encrypted_size;
    POSIX_ENSURE_REF(encrypted.data);

    POSIX_GUARD_RESULT(s2n_test_rsa_pkcs1_v15_padding_encrypt(conn, shared_key, &encrypted));

    POSIX_GUARD(s2n_pkey_free(&conn->handshake_params.server_public_key));

    return S2N_SUCCESS;
}

struct s2n_test_async_pkey_cb_ctx {
    uint32_t async_invoked_count;
    uint32_t offload_invoked_count;
};

static int s2n_test_async_pkey_decrypt_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op_in)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(op_in);

    DEFER_CLEANUP(struct s2n_async_pkey_op *op = op_in, s2n_async_pkey_op_free_pointer);

    struct s2n_test_async_pkey_cb_ctx *ctx = s2n_connection_get_ctx(conn);
    POSIX_ENSURE_REF(ctx);
    ctx->async_invoked_count += 1;

    s2n_async_pkey_op_type op_type = 0;
    EXPECT_SUCCESS(s2n_async_pkey_op_get_op_type(op, &op_type));
    EXPECT_EQUAL(op_type, S2N_ASYNC_DECRYPT);

    struct s2n_cert_chain_and_key *chain_and_key = s2n_connection_get_selected_cert(conn);
    EXPECT_NOT_NULL(chain_and_key);
    s2n_cert_private_key *pkey = s2n_cert_chain_and_key_get_private_key(chain_and_key);
    EXPECT_NOT_NULL(pkey);

    EXPECT_SUCCESS(s2n_async_pkey_op_perform(op, pkey));
    EXPECT_SUCCESS(s2n_async_pkey_op_apply(op, conn));

    return S2N_SUCCESS;
}

static int s2n_test_offload_pkey_decrypt_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op_in)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(op_in);

    DEFER_CLEANUP(struct s2n_async_pkey_op *op = op_in, s2n_async_pkey_op_free_pointer);

    struct s2n_test_async_pkey_cb_ctx *ctx = s2n_connection_get_ctx(conn);
    POSIX_ENSURE_REF(ctx);
    ctx->offload_invoked_count += 1;

    s2n_async_pkey_op_type op_type = 0;
    EXPECT_SUCCESS(s2n_async_pkey_op_get_op_type(op, &op_type));
    EXPECT_EQUAL(op_type, S2N_ASYNC_DECRYPT);

    struct s2n_cert_chain_and_key *chain_and_key = s2n_connection_get_selected_cert(conn);
    EXPECT_NOT_NULL(chain_and_key);
    s2n_cert_private_key *pkey = s2n_cert_chain_and_key_get_private_key(chain_and_key);
    EXPECT_NOT_NULL(pkey);

    uint8_t input_data[4096] = { 0 };
    struct s2n_blob input_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&input_blob, input_data, sizeof(input_data)));

    uint32_t input_size = 0;
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input_size(op, &input_size));
    EXPECT_TRUE(input_size <= input_blob.size);
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input(op, input_data, sizeof(input_data)));
    input_blob.size = input_size;

    uint8_t output_data[S2N_TLS_SECRET_LEN] = { 0 };
    struct s2n_blob output_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&output_blob, output_data, sizeof(output_data)));

    EXPECT_SUCCESS(s2n_pkey_decrypt(pkey, &input_blob, &output_blob));
    EXPECT_SUCCESS(s2n_async_pkey_op_set_output(op, output_blob.data, output_blob.size));
    EXPECT_SUCCESS(s2n_async_pkey_op_apply(op, conn));

    return S2N_SUCCESS;
}

typedef enum {
    S2N_PKEY_TEST_DEFAULT,
    S2N_PKEY_TEST_ASYNC,
    S2N_PKEY_TEST_OFFLOAD,
    S2N_PKEY_TEST_COUNT,
} s2n_pkey_test_mode;

static S2N_RESULT s2n_validate_test_async_pkey_ctx(struct s2n_test_async_pkey_cb_ctx *ctx, s2n_pkey_test_mode pkey_mode)
{
    RESULT_ENSURE_REF(ctx);

    switch (pkey_mode) {
        case S2N_PKEY_TEST_DEFAULT:
            RESULT_ENSURE_EQ(ctx->async_invoked_count, 0);
            RESULT_ENSURE_EQ(ctx->offload_invoked_count, 0);
            break;
        case S2N_PKEY_TEST_ASYNC:
            RESULT_ENSURE_EQ(ctx->async_invoked_count, 1);
            RESULT_ENSURE_EQ(ctx->offload_invoked_count, 0);
            break;
        case S2N_PKEY_TEST_OFFLOAD:
            RESULT_ENSURE_EQ(ctx->async_invoked_count, 0);
            RESULT_ENSURE_EQ(ctx->offload_invoked_count, 1);
            break;
        default:
            RESULT_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: same error + location for all Bleichenbacher attack cases.
     *
     * This doesn't prove safety, since Bleichenbacher is a timing side-channel attack. But if this
     * test DOES fail, we likely have an issue.
     */
    for (size_t pkey_test_mode = 0; pkey_test_mode < S2N_PKEY_TEST_COUNT; pkey_test_mode++) {
        /* We must use an RSA cert so that we can test RSA kex */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *rsa_cert_chain = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_cert_chain,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        struct s2n_pkey *rsa_private_key = s2n_cert_chain_and_key_get_private_key(rsa_cert_chain);
        EXPECT_NOT_NULL(rsa_private_key);
        uint32_t key_size = 0;
        EXPECT_OK(s2n_pkey_size(rsa_private_key, &key_size));
        EXPECT_TRUE(key_size > 0);

        struct s2n_kex rsa_kex = s2n_rsa;
        rsa_kex.client_key_send = s2n_test_rsa_client_key_send;

        struct s2n_cipher_suite rsa_kex_cipher_suite = s2n_rsa_with_aes_128_gcm_sha256;
        rsa_kex_cipher_suite.key_exchange_alg = &rsa_kex;

        struct s2n_cipher_suite *rsa_kex_cipher_suites[1] = { &rsa_kex_cipher_suite };
        struct s2n_cipher_preferences rsa_kex_cipher_pref = {
            .suites = rsa_kex_cipher_suites,
            .count = 1,
        };
        struct s2n_security_policy test_rsa_policy = security_policy_test_all;
        test_rsa_policy.cipher_preferences = &rsa_kex_cipher_pref;

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
        client_config->security_policy = &test_rsa_policy;

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_cert_chain));
        server_config->security_policy = &test_rsa_policy;

        if (pkey_test_mode == S2N_PKEY_TEST_ASYNC) {
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, s2n_test_async_pkey_decrypt_callback));
        } else if (pkey_test_mode == S2N_PKEY_TEST_OFFLOAD) {
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, s2n_test_offload_pkey_decrypt_callback));
        }

        /* Sanity check: ensure s2n_test_rsa_client_key_send sends a valid premaster secret by default */
        for (size_t i = 0; i < 100; i++) {
            struct s2n_test_rsa_client_key_send_ctx rsa_send_ctx = { 0 };

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
            EXPECT_SUCCESS(s2n_connection_set_ctx(client, &rsa_send_ctx));

            struct s2n_test_async_pkey_cb_ctx async_pkey_ctx = { 0 };

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));
            EXPECT_SUCCESS(s2n_connection_set_ctx(server, &async_pkey_ctx));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

            EXPECT_OK(s2n_validate_test_async_pkey_ctx(&async_pkey_ctx, pkey_test_mode));
        }

        /* All the tests for the Bleichenbacher attack cases should result in the same error from
         * s2n_aead_cipher_aes_gcm.c. However, the line number of the error can change depending on
         * how s2n-tls is built. s2n_sterror_source() is called from the first test case to
         * determine the expected error source for the remaining tests.
         */
        int expected_error = S2N_ERR_DECRYPT;
        const char *expected_source_str = NULL;

        /* Test: client sends invalid premaster secret */
        {
            struct s2n_test_rsa_client_key_send_ctx ctx = {
                .invalidate_padded_premaster_secret = true,
                .invalidate_index = key_size - 1,
            };

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
            EXPECT_SUCCESS(s2n_connection_set_ctx(client, &ctx));

            struct s2n_test_async_pkey_cb_ctx async_pkey_ctx = { 0 };

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));
            EXPECT_SUCCESS(s2n_connection_set_ctx(server, &async_pkey_ctx));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            EXPECT_FAILURE_WITH_ERRNO_NO_RESET(s2n_negotiate_test_server_and_client(server, client), expected_error);
            expected_source_str = s2n_strerror_source(s2n_errno);

            /* Ensure that the error came from s2n_aead_cipher_aes_gcm.c. */
            EXPECT_NOT_NULL(strstr(expected_source_str, "s2n_aead_cipher_aes_gcm.c"));

            EXPECT_OK(s2n_validate_test_async_pkey_ctx(&async_pkey_ctx, pkey_test_mode));
        }

        /* Test: wrong version */
        for (uint8_t version = 0; version < S2N_TLS13 + 10; version++) {
            struct s2n_test_rsa_client_key_send_ctx rsa_send_ctx = {
                .override_premaster_secret_version = true,
                .version = version,
            };

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
            EXPECT_SUCCESS(s2n_connection_set_ctx(client, &rsa_send_ctx));

            struct s2n_test_async_pkey_cb_ctx async_pkey_ctx = { 0 };

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));
            EXPECT_SUCCESS(s2n_connection_set_ctx(server, &async_pkey_ctx));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            if (version == S2N_TLS12) {
                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
            } else {
                EXPECT_FAILURE_WITH_ERRNO_NO_RESET(s2n_negotiate_test_server_and_client(server, client),
                        expected_error);
                EXPECT_STRING_EQUAL(s2n_strerror_source(s2n_errno), expected_source_str);
            }

            EXPECT_OK(s2n_validate_test_async_pkey_ctx(&async_pkey_ctx, pkey_test_mode));
        }

        /* Test: wrong plaintext size */
        for (uint32_t size = 0; size <= S2N_TLS_SECRET_LEN; size++) {
            struct s2n_test_rsa_client_key_send_ctx ctx = {
                .override_premaster_secret_size = true,
                .size = size,
            };

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
            EXPECT_SUCCESS(s2n_connection_set_ctx(client, &ctx));

            struct s2n_test_async_pkey_cb_ctx async_pkey_ctx = { 0 };

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));
            EXPECT_SUCCESS(s2n_connection_set_ctx(server, &async_pkey_ctx));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            if (size == S2N_TLS_SECRET_LEN) {
                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
            } else {
                EXPECT_FAILURE_WITH_ERRNO_NO_RESET(s2n_negotiate_test_server_and_client(server, client),
                        expected_error);
                EXPECT_STRING_EQUAL(s2n_strerror_source(s2n_errno), expected_source_str);
            }

            EXPECT_OK(s2n_validate_test_async_pkey_ctx(&async_pkey_ctx, pkey_test_mode));
        }

        /* Test: wrong padding
         *
         * Each of the padding bytes are invalidated before encrypting, and the resulting
         * ciphertext is sent to the server. PKCS1 v1.5 padding starts at 0 and ends before the
         * plaintext.
         */
        for (uint32_t invalidate_index = 0; invalidate_index < key_size - S2N_TLS_SECRET_LEN; invalidate_index++) {
            struct s2n_test_rsa_client_key_send_ctx ctx = {
                .invalidate_padded_premaster_secret = true,
                .invalidate_index = invalidate_index,
            };

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
            EXPECT_SUCCESS(s2n_connection_set_ctx(client, &ctx));

            struct s2n_test_async_pkey_cb_ctx async_pkey_ctx = { 0 };

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));
            EXPECT_SUCCESS(s2n_connection_set_ctx(server, &async_pkey_ctx));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            EXPECT_FAILURE_WITH_ERRNO_NO_RESET(s2n_negotiate_test_server_and_client(server, client), expected_error);
            EXPECT_STRING_EQUAL(s2n_strerror_source(s2n_errno), expected_source_str);

            EXPECT_OK(s2n_validate_test_async_pkey_ctx(&async_pkey_ctx, pkey_test_mode));
        }
    }

    END_TEST();
}
