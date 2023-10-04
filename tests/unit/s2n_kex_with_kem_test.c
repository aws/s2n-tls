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

#include "pq-crypto/s2n_pq.h"
#include "tests/s2n_test.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_client_key_exchange.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_kex_data.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_server_key_exchange.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

static struct s2n_kex s2n_test_kem_kex = {
    .server_key_recv_read_data = &s2n_kem_server_key_recv_read_data,
    .server_key_recv_parse_data = &s2n_kem_server_key_recv_parse_data,
    .server_key_send = &s2n_kem_server_key_send,
    .client_key_recv = &s2n_kem_client_key_recv,
    .client_key_send = &s2n_kem_client_key_send,
};

static struct s2n_cipher_suite kyber_test_suite = {
    .iana_value = { TLS_ECDHE_KYBER_RSA_WITH_AES_256_GCM_SHA384 },
    .key_exchange_alg = &s2n_test_kem_kex,
};

static int do_kex_with_kem(struct s2n_cipher_suite *cipher_suite, const char *security_policy_version, const struct s2n_kem *negotiated_kem)
{
    struct s2n_connection *client_conn;
    struct s2n_connection *server_conn;

    POSIX_GUARD_PTR(client_conn = s2n_connection_new(S2N_CLIENT));
    POSIX_GUARD_PTR(server_conn = s2n_connection_new(S2N_SERVER));

    const struct s2n_security_policy *security_policy = NULL;
    POSIX_GUARD(s2n_find_security_policy_from_version(security_policy_version, &security_policy));
    POSIX_GUARD_PTR(security_policy);

    client_conn->kex_params.kem_params.kem = negotiated_kem;
    client_conn->secure->cipher_suite = cipher_suite;
    client_conn->security_policy_override = security_policy;

    server_conn->kex_params.kem_params.kem = negotiated_kem;
    server_conn->secure->cipher_suite = cipher_suite;
    server_conn->security_policy_override = security_policy;

    /* Part 1: Server calls send_key */
    struct s2n_blob data_to_sign = { 0 };
    POSIX_GUARD(s2n_kem_server_key_send(server_conn, &data_to_sign));
    /* 2 extra bytes for the kem extension id and 2 additional bytes for the length of the public key sent over the wire. */
    const uint32_t KEM_PUBLIC_KEY_MESSAGE_SIZE = (*negotiated_kem).public_key_length + 4;
    POSIX_ENSURE_EQ(data_to_sign.size, KEM_PUBLIC_KEY_MESSAGE_SIZE);

    POSIX_ENSURE_EQ((*negotiated_kem).private_key_length, server_conn->kex_params.kem_params.private_key.size);
    struct s2n_blob server_key_message = { .size = KEM_PUBLIC_KEY_MESSAGE_SIZE, .data = s2n_stuffer_raw_read(&server_conn->handshake.io, KEM_PUBLIC_KEY_MESSAGE_SIZE) };
    POSIX_GUARD_PTR(server_key_message.data);

    /* The KEM public key should get written directly to the server's handshake IO; kem_params.public_key
     * should point to NULL */
    POSIX_ENSURE_EQ(NULL, server_conn->kex_params.kem_params.public_key.data);
    POSIX_ENSURE_EQ(0, server_conn->kex_params.kem_params.public_key.size);

    /* Part 1.1: feed that to the client */
    POSIX_GUARD(s2n_stuffer_write(&client_conn->handshake.io, &server_key_message));

    /* Part 2: Client calls recv_read and recv_parse */
    struct s2n_kex_raw_server_data raw_params = { 0 };
    struct s2n_blob data_to_verify = { 0 };
    POSIX_GUARD(s2n_kem_server_key_recv_read_data(client_conn, &data_to_verify, &raw_params));
    POSIX_ENSURE_EQ(data_to_verify.size, KEM_PUBLIC_KEY_MESSAGE_SIZE);

    if (s2n_kem_server_key_recv_parse_data(client_conn, &raw_params) != 0) {
        /* Tests with incompatible parameters are expected to fail here;
         * we want to clean up the connections before failing. */
        POSIX_GUARD(s2n_connection_free(client_conn));
        POSIX_GUARD(s2n_connection_free(server_conn));
        S2N_ERROR_PRESERVE_ERRNO();
    }

    POSIX_ENSURE_EQ((*negotiated_kem).public_key_length, client_conn->kex_params.kem_params.public_key.size);

    /* Part 3: Client calls send_key. The additional 2 bytes are for the ciphertext length sent over the wire */
    const uint32_t KEM_CIPHERTEXT_MESSAGE_SIZE = (*negotiated_kem).ciphertext_length + 2;
    struct s2n_blob *client_shared_key = &(client_conn->kex_params.kem_params.shared_secret);
    POSIX_GUARD(s2n_kem_client_key_send(client_conn, client_shared_key));
    struct s2n_blob client_key_message = { .size = KEM_CIPHERTEXT_MESSAGE_SIZE, .data = s2n_stuffer_raw_read(&client_conn->handshake.io, KEM_CIPHERTEXT_MESSAGE_SIZE) };
    POSIX_GUARD_PTR(client_key_message.data);

    /* Part 3.1: Send that back to the server */
    POSIX_GUARD(s2n_stuffer_write(&server_conn->handshake.io, &client_key_message));

    /* Part 4: Call client key recv */
    struct s2n_blob *server_shared_key = &(server_conn->kex_params.kem_params.shared_secret);
    POSIX_GUARD(s2n_kem_client_key_recv(server_conn, server_shared_key));
    POSIX_ENSURE_EQ(memcmp(client_shared_key->data, server_shared_key->data, (*negotiated_kem).shared_secret_key_length), 0);

    POSIX_GUARD(s2n_connection_free(client_conn));
    POSIX_GUARD(s2n_connection_free(server_conn));

    return 0;
}

static int assert_pq_disabled_checks(struct s2n_cipher_suite *cipher_suite, const char *security_policy_version, const struct s2n_kem *negotiated_kem)
{
    struct s2n_connection *server_conn;
    POSIX_GUARD_PTR(server_conn = s2n_connection_new(S2N_SERVER));
    const struct s2n_security_policy *security_policy = NULL;
    POSIX_GUARD(s2n_find_security_policy_from_version(security_policy_version, &security_policy));
    POSIX_GUARD_PTR(security_policy);
    server_conn->kex_params.kem_params.kem = negotiated_kem;
    server_conn->secure->cipher_suite = cipher_suite;
    server_conn->security_policy_override = security_policy;

    /* If PQ is disabled:
     * s2n_check_kem() (s2n_hybrid_ecdhe_kem.connection_supported) should indicate that the connection is not supported
     * s2n_configure_kem() (s2n_hybrid_ecdhe_kem.configure_connection) should return S2N_RESULT_ERROR
     *     set s2n_errno to S2N_ERR_PQ_DISABLED */
    bool connection_supported = true;
    POSIX_GUARD_RESULT(s2n_hybrid_ecdhe_kem.connection_supported(cipher_suite, server_conn, &connection_supported));
    POSIX_ENSURE_EQ(connection_supported, false);

    POSIX_ENSURE_EQ(s2n_result_is_error(s2n_hybrid_ecdhe_kem.configure_connection(cipher_suite, server_conn)), true);

    POSIX_ENSURE_EQ(s2n_errno, S2N_ERR_PQ_DISABLED);

    POSIX_GUARD(s2n_connection_free(server_conn));
    s2n_errno = 0;
    s2n_debug_info_reset();

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    if (!s2n_pq_is_enabled()) {
        /* Verify s2n_check_kem() and s2n_configure_kem() are performing their pq-enabled checks appropriately. */
        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-07", &s2n_kyber_512_r3));

        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "PQ-TLS-1-1-2021-05-17", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "PQ-TLS-1-0-2021-05-18", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "PQ-TLS-1-0-2021-05-19", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "PQ-TLS-1-0-2021-05-20", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "PQ-TLS-1-1-2021-05-21", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "PQ-TLS-1-0-2021-05-22", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "PQ-TLS-1-0-2021-05-23", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "PQ-TLS-1-0-2021-05-24", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "PQ-TLS-1-0-2021-05-25", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(assert_pq_disabled_checks(&kyber_test_suite, "PQ-TLS-1-0-2021-05-26", &s2n_kyber_512_r3));

    } else {
        EXPECT_SUCCESS(do_kex_with_kem(&kyber_test_suite, "PQ-TLS-1-1-2021-05-17", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(do_kex_with_kem(&kyber_test_suite, "PQ-TLS-1-0-2021-05-18", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(do_kex_with_kem(&kyber_test_suite, "PQ-TLS-1-0-2021-05-19", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(do_kex_with_kem(&kyber_test_suite, "PQ-TLS-1-0-2021-05-20", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(do_kex_with_kem(&kyber_test_suite, "PQ-TLS-1-1-2021-05-21", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(do_kex_with_kem(&kyber_test_suite, "PQ-TLS-1-0-2021-05-22", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(do_kex_with_kem(&kyber_test_suite, "PQ-TLS-1-0-2021-05-23", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(do_kex_with_kem(&kyber_test_suite, "PQ-TLS-1-0-2021-05-24", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(do_kex_with_kem(&kyber_test_suite, "PQ-TLS-1-0-2021-05-25", &s2n_kyber_512_r3));
        EXPECT_SUCCESS(do_kex_with_kem(&kyber_test_suite, "PQ-TLS-1-0-2021-05-26", &s2n_kyber_512_r3));
    }

    END_TEST();
}
