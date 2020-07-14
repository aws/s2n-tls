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

#include "tests/s2n_test.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_client_key_exchange.h"
#include "tls/s2n_server_key_exchange.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_kex_data.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_security_policies.h"
#include "crypto/s2n_fips.h"

#include "utils/s2n_safety.h"

#if !defined(S2N_NO_PQ)
static struct s2n_kex s2n_test_kem_kex = {
        .server_key_recv_read_data = &s2n_kem_server_key_recv_read_data,
        .server_key_recv_parse_data = &s2n_kem_server_key_recv_parse_data,
        .server_key_send = &s2n_kem_server_key_send,
        .client_key_recv = &s2n_kem_client_key_recv,
        .client_key_send = &s2n_kem_client_key_send,
};

static struct s2n_cipher_suite sike_test_suite = {
        .iana_value = { TLS_ECDHE_SIKE_RSA_WITH_AES_256_GCM_SHA384 },
        .key_exchange_alg = &s2n_test_kem_kex,
};

static struct s2n_cipher_suite bike_test_suite = {
        .iana_value = { TLS_ECDHE_BIKE_RSA_WITH_AES_256_GCM_SHA384 },
        .key_exchange_alg = &s2n_test_kem_kex,
};

static struct s2n_cipher_suite kyber_test_suite = {
        .iana_value = { TLS_ECDHE_KYBER_RSA_WITH_AES_256_GCM_SHA384 },
        .key_exchange_alg = &s2n_test_kem_kex,
};

static int do_kex_with_kem(struct s2n_cipher_suite *cipher_suite, const char *security_policy_version, const struct s2n_kem *negotiated_kem) {
    S2N_ERROR_IF(s2n_is_in_fips_mode(), S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);

    struct s2n_connection *client_conn;
    struct s2n_connection *server_conn;

    GUARD_NONNULL(client_conn = s2n_connection_new(S2N_CLIENT));
    GUARD_NONNULL(server_conn = s2n_connection_new(S2N_SERVER));

    const struct s2n_security_policy *security_policy = NULL;
    GUARD(s2n_find_security_policy_from_version(security_policy_version, &security_policy));
    GUARD_NONNULL(security_policy);

    client_conn->secure.kem_params.kem = negotiated_kem;
    client_conn->secure.cipher_suite = cipher_suite;
    client_conn->security_policy_override = security_policy;

    server_conn->secure.kem_params.kem = negotiated_kem;
    server_conn->secure.cipher_suite = cipher_suite;
    server_conn->security_policy_override = security_policy;

    /* Part 1: Server calls send_key */
    struct s2n_blob data_to_sign = {0};
    GUARD(s2n_kem_server_key_send(server_conn, &data_to_sign));
    /* 2 extra bytes for the kem extension id and 2 additional bytes for the length of the public key sent over the wire. */
    const uint32_t KEM_PUBLIC_KEY_MESSAGE_SIZE = (*negotiated_kem).public_key_length + 4;
    eq_check(data_to_sign.size, KEM_PUBLIC_KEY_MESSAGE_SIZE);

    eq_check((*negotiated_kem).private_key_length, server_conn->secure.kem_params.private_key.size);
    struct s2n_blob server_key_message = {.size = KEM_PUBLIC_KEY_MESSAGE_SIZE, .data = s2n_stuffer_raw_read(&server_conn->handshake.io,
            KEM_PUBLIC_KEY_MESSAGE_SIZE)};
    GUARD_NONNULL(server_key_message.data);

    /* The KEM public key should get written directly to the server's handshake IO; kem_params.public_key
     * should point to NULL */
    eq_check(NULL, server_conn->secure.kem_params.public_key.data);
    eq_check(0, server_conn->secure.kem_params.public_key.size);

    /* Part 1.1: feed that to the client */
    GUARD(s2n_stuffer_write(&client_conn->handshake.io, &server_key_message));

    /* Part 2: Client calls recv_read and recv_parse */
    struct s2n_kex_raw_server_data raw_params = {0};
    struct s2n_blob data_to_verify = {0};
    GUARD(s2n_kem_server_key_recv_read_data(client_conn, &data_to_verify, &raw_params));
    eq_check(data_to_verify.size, KEM_PUBLIC_KEY_MESSAGE_SIZE);

    if (s2n_kem_server_key_recv_parse_data(client_conn, &raw_params) != 0) {
        /* Tests with incompatible parameters are expected to fail here;
         * we want to clean up the connections before failing. */
        GUARD(s2n_connection_free(client_conn));
        GUARD(s2n_connection_free(server_conn));
        S2N_ERROR_PRESERVE_ERRNO();
    }

    eq_check((*negotiated_kem).public_key_length, client_conn->secure.kem_params.public_key.size);

    /* Part 3: Client calls send_key. The additional 2 bytes are for the ciphertext length sent over the wire */
    const uint32_t KEM_CIPHERTEXT_MESSAGE_SIZE = (*negotiated_kem).ciphertext_length + 2;
    struct s2n_blob *client_shared_key = &(client_conn->secure.kem_params.shared_secret);
    GUARD(s2n_kem_client_key_send(client_conn, client_shared_key));
    struct s2n_blob client_key_message = {.size = KEM_CIPHERTEXT_MESSAGE_SIZE, .data = s2n_stuffer_raw_read(&client_conn->handshake.io,
            KEM_CIPHERTEXT_MESSAGE_SIZE)};
    GUARD_NONNULL(client_key_message.data);

    /* Part 3.1: Send that back to the server */
    GUARD(s2n_stuffer_write(&server_conn->handshake.io, &client_key_message));

    /* Part 4: Call client key recv */
    struct s2n_blob *server_shared_key = &(server_conn->secure.kem_params.shared_secret);
    GUARD(s2n_kem_client_key_recv(server_conn, server_shared_key));
    eq_check(memcmp(client_shared_key->data, server_shared_key->data, (*negotiated_kem).shared_secret_key_length), 0);

    GUARD(s2n_connection_free(client_conn));
    GUARD(s2n_connection_free(server_conn));

    return 0;
}

static int assert_kex_fips_checks(struct s2n_cipher_suite *cipher_suite, const char *security_policy_version, const struct s2n_kem *negotiated_kem) {
    if (!s2n_is_in_fips_mode()) {
        /* This function should only be called when FIPS mode is enabled */
        return S2N_FAILURE;
    }

    struct s2n_connection *server_conn;
    GUARD_NONNULL(server_conn = s2n_connection_new(S2N_SERVER));
    const struct s2n_security_policy *security_policy = NULL;
    GUARD(s2n_find_security_policy_from_version(security_policy_version, &security_policy));
    GUARD_NONNULL(security_policy);
    server_conn->secure.kem_params.kem = negotiated_kem;
    server_conn->secure.cipher_suite = cipher_suite;
    server_conn->security_policy_override = security_policy;

    /* If in FIPS mode:
     * s2n_check_kem() (s2n_hybrid_ecdhe_kem.connection_supported) should return 0
     * s2n_configure_kem() (s2n_hybrid_ecdhe_kem.configure_connection) should return -1 and
     *     set s2n_errno to S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS */
    int ret_val = (s2n_hybrid_ecdhe_kem.connection_supported(cipher_suite, server_conn) != 0) &&
                  (s2n_hybrid_ecdhe_kem.configure_connection(cipher_suite, server_conn) != S2N_FAILURE) &&
                  (s2n_errno != S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);

    GUARD(s2n_connection_free(server_conn));
    s2n_errno = 0;
    s2n_debug_str = NULL;

    return ret_val;
}
#endif

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if !defined(S2N_NO_PQ)

    if (s2n_is_in_fips_mode()) {
        /* There is no support for PQ KEMs while in FIPS mode. So we verify functions s2n_check_kem() and
         * s2n_configure_kem() (in s2n_kex.c) are performing their FIPS checks appropriately. */
        EXPECT_SUCCESS(assert_kex_fips_checks(&sike_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_sike_p503_r1));
        EXPECT_SUCCESS(assert_kex_fips_checks(&sike_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_sike_p434_r2));
        EXPECT_SUCCESS(assert_kex_fips_checks(&sike_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_sike_p503_r1));
        EXPECT_SUCCESS(assert_kex_fips_checks(&sike_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_sike_p434_r2));

        EXPECT_SUCCESS(assert_kex_fips_checks(&bike_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_bike1_l1_r1));
        EXPECT_SUCCESS(assert_kex_fips_checks(&bike_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_bike1_l1_r2));
        EXPECT_SUCCESS(assert_kex_fips_checks(&bike_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_bike1_l1_r1));
        EXPECT_SUCCESS(assert_kex_fips_checks(&bike_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_bike1_l1_r2));

        EXPECT_SUCCESS(assert_kex_fips_checks(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-07", &s2n_kyber_512_r2));
    } else {
        /* KMS-PQ-TLS-1-0-2019-06 supports only Round 1 KEMs
         * KMS-PQ-TLS-1-0-2020-02 supports Round 1 and Round 2 KEMs */
        EXPECT_SUCCESS(do_kex_with_kem(&sike_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_sike_p503_r1));
        EXPECT_SUCCESS(do_kex_with_kem(&sike_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_sike_p503_r1));
        EXPECT_SUCCESS(do_kex_with_kem(&sike_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_sike_p434_r2));
        EXPECT_SUCCESS(do_kex_with_kem(&sike_test_suite, "KMS-PQ-TLS-1-0-2020-07", &s2n_sike_p503_r1));
        EXPECT_SUCCESS(do_kex_with_kem(&sike_test_suite, "KMS-PQ-TLS-1-0-2020-07", &s2n_sike_p434_r2));

        EXPECT_SUCCESS(do_kex_with_kem(&bike_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_bike1_l1_r1));
        EXPECT_SUCCESS(do_kex_with_kem(&bike_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_bike1_l1_r1));
        EXPECT_SUCCESS(do_kex_with_kem(&bike_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_bike1_l1_r2));
        EXPECT_SUCCESS(do_kex_with_kem(&bike_test_suite, "KMS-PQ-TLS-1-0-2020-07", &s2n_bike1_l1_r1));
        EXPECT_SUCCESS(do_kex_with_kem(&bike_test_suite, "KMS-PQ-TLS-1-0-2020-07", &s2n_bike1_l1_r2));

        EXPECT_SUCCESS(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-07", &s2n_kyber_512_r2));

        /* Test Failure cases */
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&sike_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_sike_p434_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&sike_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_bike1_l1_r1), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&sike_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_bike1_l1_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&sike_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_bike1_l1_r1), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&sike_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_bike1_l1_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);

        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&bike_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_bike1_l1_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&bike_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_sike_p434_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&bike_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_sike_p503_r1), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&bike_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_sike_p434_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&bike_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_sike_p503_r1), S2N_ERR_KEM_UNSUPPORTED_PARAMS);

        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_bike1_l1_r1), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_bike1_l1_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_sike_p503_r1), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_sike_p434_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2019-06", &s2n_kyber_512_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);

        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_bike1_l1_r1), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_bike1_l1_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_sike_p503_r1), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_sike_p434_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-02", &s2n_kyber_512_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);

        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-07", &s2n_bike1_l1_r1), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-07", &s2n_bike1_l1_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-07", &s2n_sike_p503_r1), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        EXPECT_FAILURE_WITH_ERRNO(do_kex_with_kem(&kyber_test_suite, "KMS-PQ-TLS-1-0-2020-07", &s2n_sike_p434_r2), S2N_ERR_KEM_UNSUPPORTED_PARAMS);
    }

#endif

    END_TEST();
}
