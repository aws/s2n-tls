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

#include "tls/s2n_signature_algorithms.h"

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_signature_scheme.h"
#include "tls/s2n_tls.h"

#define LENGTH       (s2n_array_len(test_signature_schemes))
#define STUFFER_SIZE (LENGTH * TLS_SIGNATURE_SCHEME_LEN + 10)

#define RSA_CIPHER_SUITE   &s2n_ecdhe_rsa_with_aes_128_cbc_sha
#define ECDSA_CIPHER_SUITE &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha
#define TLS13_CIPHER_SUITE &s2n_tls13_aes_128_gcm_sha256

/* The only TLS1.3-only signature schemes are RSA-PSS-PSS, which
 * are difficult to test with due to mixed libcrypto support.
 * Use a test scheme instead.
 */
const struct s2n_signature_scheme s2n_test_tls13_ecdsa_sha384 = {
    .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SHA384,
    .hash_alg = S2N_HASH_SHA384,
    .sig_alg = S2N_SIGNATURE_ECDSA,
    .libcrypto_nid = NID_ecdsa_with_SHA384,
    .signature_curve = &s2n_ecc_curve_secp384r1,
    /* Only supports TLS1.3 for testing */
    .minimum_protocol_version = S2N_TLS13,
};

const struct s2n_signature_scheme *const test_signature_schemes[] = {
    &s2n_test_tls13_ecdsa_sha384,
    &s2n_rsa_pkcs1_sha256,
    &s2n_rsa_pkcs1_sha224,
    &s2n_rsa_pkcs1_sha1,
    &s2n_ecdsa_sha1,
    &s2n_ecdsa_sha256,
};

const struct s2n_signature_preferences test_preferences = {
    .count = LENGTH,
    .signature_schemes = test_signature_schemes,
};

struct s2n_local_sig_schemes_context {
    struct s2n_security_policy policy;
    struct s2n_signature_preferences signature_prefs;
};
static S2N_RESULT s2n_test_set_local_sig_schemes(struct s2n_connection *conn,
        struct s2n_local_sig_schemes_context *context,
        const struct s2n_signature_scheme **sig_schemes, size_t count)
{
    RESULT_ENSURE_REF(context);

    context->signature_prefs.signature_schemes = sig_schemes;
    context->signature_prefs.count = count;

    const struct s2n_security_policy *curr_policy = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_security_policy(conn, &curr_policy));

    context->policy = *curr_policy;
    context->policy.signature_preferences = &context->signature_prefs;
    conn->security_policy_override = &context->policy;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_set_peer_sig_schemes(struct s2n_sig_scheme_list *peer_list,
        const struct s2n_signature_scheme **sig_schemes, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        peer_list->iana_list[i] = sig_schemes[i]->iana_value;
    }
    peer_list->len = count;
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *rsa_cert_chain = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_cert_chain,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_cert_chain = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_cert_chain,
            S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));

    struct s2n_cert_chain_and_key *certs[] = { ecdsa_cert_chain, rsa_cert_chain };

    /* s2n_signature_algorithms_supported_list_send */
    {
        struct s2n_security_policy test_security_policy = *s2n_fetch_default_config()->security_policy;
        test_security_policy.signature_preferences = &test_preferences;

        /* Test: if all signatures supported, send all signatures */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->security_policy_override = &test_security_policy;
            conn->actual_protocol_version = S2N_TLS13;

            DEFER_CLEANUP(struct s2n_stuffer result = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&result, 0));
            EXPECT_OK(s2n_signature_algorithms_supported_list_send(conn, &result));

            uint16_t size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &size));
            EXPECT_EQUAL(size, s2n_stuffer_data_available(&result));

            for (size_t i = 0; i < s2n_array_len(test_signature_schemes); i++) {
                uint16_t iana_value = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &iana_value));
                EXPECT_EQUAL(iana_value, test_signature_schemes[i]->iana_value);
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);
        };

        /* Test: do not send unsupported signatures */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->security_policy_override = &test_security_policy;
            conn->actual_protocol_version = S2N_TLS12;

            DEFER_CLEANUP(struct s2n_stuffer result = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&result, 0));
            EXPECT_OK(s2n_signature_algorithms_supported_list_send(conn, &result));

            uint16_t size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &size));
            EXPECT_EQUAL(size, s2n_stuffer_data_available(&result));

            for (size_t i = 0; i < s2n_array_len(test_signature_schemes); i++) {
                if (test_signature_schemes[i] != &s2n_test_tls13_ecdsa_sha384) {
                    uint16_t iana_value = 0;
                    EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &iana_value));
                    EXPECT_EQUAL(iana_value, test_signature_schemes[i]->iana_value);
                }
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);
        };

        /* Test: written signatures readable */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->security_policy_override = &test_security_policy;
            conn->actual_protocol_version = S2N_TLS13;

            DEFER_CLEANUP(struct s2n_stuffer result = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&result, 0));
            EXPECT_OK(s2n_signature_algorithms_supported_list_send(conn, &result));

            struct s2n_sig_scheme_list signatures = { 0 };
            EXPECT_SUCCESS(s2n_recv_supported_sig_scheme_list(&result, &signatures));
            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);

            EXPECT_EQUAL(signatures.len, s2n_array_len(test_signature_schemes));
            for (size_t i = 0; i < s2n_array_len(test_signature_schemes); i++) {
                EXPECT_EQUAL(signatures.iana_list[i], test_signature_schemes[i]->iana_value);
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);
        };

        /* Test: do not send TLS1.2 signature schemes if QUIC enabled */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->security_policy_override = &test_security_policy;
            conn->actual_protocol_version = S2N_TLS13;
            conn->quic_enabled = true;

            DEFER_CLEANUP(struct s2n_stuffer result = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&result, 0));
            EXPECT_OK(s2n_signature_algorithms_supported_list_send(conn, &result));

            uint16_t size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &size));
            EXPECT_EQUAL(size, s2n_stuffer_data_available(&result));

            for (size_t i = 0; i < s2n_array_len(test_signature_schemes); i++) {
                if (test_signature_schemes[i]->maximum_protocol_version == 0
                        || test_signature_schemes[i]->maximum_protocol_version >= S2N_TLS13) {
                    uint16_t iana_value = 0;
                    EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &iana_value));
                    EXPECT_EQUAL(iana_value, test_signature_schemes[i]->iana_value);
                }
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);
        };
    };

    /* s2n_signature_algorithm_select */
    {
        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_cert_chain));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_cert_chain));

        /* Clients can only configure one certificate */
        DEFER_CLEANUP(struct s2n_config *client_ecdsa_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_ecdsa_config, ecdsa_cert_chain));
        DEFER_CLEANUP(struct s2n_config *client_rsa_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_rsa_config, rsa_cert_chain));

        /* TLS1.2 defaults defined by the RFC */
        const struct s2n_signature_scheme *ecdsa_default = &s2n_ecdsa_sha1;
        const struct s2n_signature_scheme *rsa_default = &s2n_rsa_pkcs1_sha1;

        /* Test: choose legacy default for <TLS1.2 */
        {
            /* Both the client and server support other signature schemes-- we're
             * just not going to choose them.
             */
            const struct s2n_signature_scheme *test_schemes[] = {
                &s2n_ecdsa_sha384,
                &s2n_rsa_pss_rsae_sha256,
                &s2n_rsa_pss_pss_sha256,
                &s2n_rsa_pkcs1_sha256,
            };

            /* Test: Client chooses default based on configured cert type */
            {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        test_schemes, s2n_array_len(test_schemes)));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        test_schemes, s2n_array_len(test_schemes)));

                /* Test: ECDSA */
                {
                    const struct s2n_signature_scheme *expected = &s2n_ecdsa_sha1;
                    conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_ECDSA;
                    EXPECT_SUCCESS(s2n_connection_set_config(conn, client_ecdsa_config));

                    /* TLS1.1 selects the default */
                    conn->actual_protocol_version = S2N_TLS11;
                    EXPECT_OK(s2n_signature_algorithm_select(conn));
                    EXPECT_EQUAL(conn->handshake_params.client_cert_sig_scheme, expected);

                    /* TLS1.2 doesn't select the default */
                    conn->actual_protocol_version = S2N_TLS12;
                    EXPECT_OK(s2n_signature_algorithm_select(conn));
                    EXPECT_NOT_EQUAL(conn->handshake_params.client_cert_sig_scheme, expected);
                };

                /* Test: RSA */
                {
                    const struct s2n_signature_scheme *expected = &s2n_rsa_pkcs1_md5_sha1;
                    conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_RSA;
                    EXPECT_SUCCESS(s2n_connection_set_config(conn, client_rsa_config));

                    /* TLS1.1 selects the default */
                    conn->actual_protocol_version = S2N_TLS11;
                    EXPECT_OK(s2n_signature_algorithm_select(conn));
                    EXPECT_EQUAL(conn->handshake_params.client_cert_sig_scheme, expected);

                    /* TLS1.2 doesn't select the default */
                    conn->actual_protocol_version = S2N_TLS12;
                    EXPECT_OK(s2n_signature_algorithm_select(conn));
                    EXPECT_NOT_EQUAL(conn->handshake_params.client_cert_sig_scheme, expected);
                };
            };

            /* Test: Server chooses default based on cipher suite */
            {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        test_schemes, s2n_array_len(test_schemes)));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        test_schemes, s2n_array_len(test_schemes)));

                /* Test: ECDSA */
                {
                    const struct s2n_signature_scheme *expected = &s2n_ecdsa_sha1;
                    conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;

                    /* TLS1.1 selects the default */
                    conn->actual_protocol_version = S2N_TLS11;
                    EXPECT_OK(s2n_signature_algorithm_select(conn));
                    EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, expected);

                    /* TLS1.2 doesn't select the default */
                    conn->actual_protocol_version = S2N_TLS12;
                    EXPECT_OK(s2n_signature_algorithm_select(conn));
                    EXPECT_NOT_EQUAL(conn->handshake_params.server_cert_sig_scheme, expected);
                };

                /* Test: RSA */
                {
                    const struct s2n_signature_scheme *expected = &s2n_rsa_pkcs1_md5_sha1;
                    conn->secure->cipher_suite = RSA_CIPHER_SUITE;

                    /* TLS1.1 selects the default */
                    conn->actual_protocol_version = S2N_TLS11;
                    EXPECT_OK(s2n_signature_algorithm_select(conn));
                    EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, expected);

                    /* TLS1.2 doesn't select the default */
                    conn->actual_protocol_version = S2N_TLS12;
                    EXPECT_OK(s2n_signature_algorithm_select(conn));
                    EXPECT_NOT_EQUAL(conn->handshake_params.server_cert_sig_scheme, expected);
                };
            };
        };

        /* Test: successfully choose server signature scheme */
        {
            const struct s2n_signature_scheme *expected = &s2n_ecdsa_sha256;

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, client_ecdsa_config));

            struct s2n_local_sig_schemes_context local_context = { 0 };
            EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context, &expected, 1));
            EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                    &expected, 1));

            EXPECT_OK(s2n_signature_algorithm_select(conn));
            EXPECT_EQUAL(conn->handshake_params.client_cert_sig_scheme, expected);
        };

        /* Test: successfully choose client signature scheme */
        {
            const struct s2n_signature_scheme *expected = &s2n_ecdsa_sha256;

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

            struct s2n_local_sig_schemes_context local_context = { 0 };
            EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context, &expected, 1));
            EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                    &expected, 1));

            EXPECT_OK(s2n_signature_algorithm_select(conn));
            EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, expected);
        };

        /* Test: choose local most preferred, not peer most preferred */
        {
            const struct s2n_signature_scheme *order[] = {
                &s2n_ecdsa_sha256,
                &s2n_ecdsa_sha384,
                &s2n_ecdsa_sha1,
            };
            const struct s2n_signature_scheme *reversed_order[] = {
                &s2n_ecdsa_sha1,
                &s2n_ecdsa_sha384,
                &s2n_ecdsa_sha256,
            };

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));
            struct s2n_local_sig_schemes_context local_context = { 0 };

            /* Local order preferred */
            {
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        order, s2n_array_len(order)));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        reversed_order, s2n_array_len(reversed_order)));

                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, order[0]);
            }

            /* Local order preferred, even when reversed */
            {
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        reversed_order, s2n_array_len(reversed_order)));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        order, s2n_array_len(order)));

                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, reversed_order[0]);
            }

            /* Local order matches peer order
             * (to prove that we're not just choosing the peer's least preferred)
             */
            {
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        order, s2n_array_len(order)));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        order, s2n_array_len(order)));

                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, order[0]);
            }
        };

        /* Test: do not choose invalid schemes */
        {
            /* Test: scheme not valid for higher protocol version */
            {
                /* Valid TLS1.3 ECDSA sig schemes include associated curves */
                const struct s2n_signature_scheme *invalid = &s2n_ecdsa_sha224;

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        &invalid, 1));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        &invalid, 1));

                /* Fails for TLS1.3 */
                conn->actual_protocol_version = S2N_TLS13;
                conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_signature_algorithm_select(conn),
                        S2N_ERR_NO_VALID_SIGNATURE_SCHEME);

                /* Succeeds for TLS1.2 */
                conn->actual_protocol_version = S2N_TLS12;
                conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
                EXPECT_OK(s2n_signature_algorithm_select(conn));
            };

            /* Test: scheme not valid for lower protocol version */
            {
                const struct s2n_signature_scheme *invalid = &s2n_test_tls13_ecdsa_sha384;

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        &invalid, 1));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        &invalid, 1));

                /* Fails for TLS1.2 */
                conn->actual_protocol_version = S2N_TLS12;
                conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_signature_algorithm_select(conn),
                        S2N_ERR_NO_VALID_SIGNATURE_SCHEME);

                /* Succeeds for TLS1.3 */
                conn->actual_protocol_version = S2N_TLS13;
                conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
                EXPECT_OK(s2n_signature_algorithm_select(conn));
            };

            /* Test: SHA1 not allowed in TLS1.3 */
            {
                /* No SHA1 signature schemes for TLS1.3 actually exist.
                 * Create one for testing.
                 */
                struct s2n_signature_scheme sha1_tls13_scheme = s2n_ecdsa_sha384;
                sha1_tls13_scheme.hash_alg = s2n_ecdsa_sha1.hash_alg;
                const struct s2n_signature_scheme *invalid = &sha1_tls13_scheme;

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                conn->actual_protocol_version = S2N_TLS13;
                conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
                EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        &invalid, 1));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        &invalid, 1));

                /* Fails with SHA1 */
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_signature_algorithm_select(conn),
                        S2N_ERR_NO_VALID_SIGNATURE_SCHEME);

                /* Succeeds without SHA1 */
                sha1_tls13_scheme.hash_alg = s2n_ecdsa_sha384.hash_alg;
                EXPECT_OK(s2n_signature_algorithm_select(conn));
            };

            /* Test: rsa-pkcs1 not allowed in TLS1.3 */
            {
                /* No pkcs1 signature schemes for TLS1.3 actually exist.
                 * Create one for testing.
                 */
                struct s2n_signature_scheme pkcs1_tls13_scheme = s2n_rsa_pss_rsae_sha256;
                pkcs1_tls13_scheme.sig_alg = s2n_rsa_pkcs1_sha256.sig_alg;
                const struct s2n_signature_scheme *invalid = &pkcs1_tls13_scheme;

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                conn->actual_protocol_version = S2N_TLS13;
                conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
                EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        &invalid, 1));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        &invalid, 1));

                /* Fails for pkcs1 */
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_signature_algorithm_select(conn),
                        S2N_ERR_NO_VALID_SIGNATURE_SCHEME);

                /* Succeeds for pss */
                if (s2n_is_rsa_pss_signing_supported()) {
                    pkcs1_tls13_scheme.sig_alg = s2n_rsa_pss_rsae_sha256.sig_alg;
                    EXPECT_OK(s2n_signature_algorithm_select(conn));
                }
            };

            /* Test: no rsa certs */
            {
                const struct s2n_signature_scheme *scheme = &s2n_rsa_pkcs1_sha256;

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                conn->actual_protocol_version = S2N_TLS12;
                conn->secure->cipher_suite = RSA_CIPHER_SUITE;

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        &scheme, 1));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        &scheme, 1));

                /* Fails for default config with no certs */
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_signature_algorithm_select(conn),
                        S2N_ERR_NO_VALID_SIGNATURE_SCHEME);

                /* Fails for config with ecdsa cert */
                EXPECT_SUCCESS(s2n_connection_set_config(conn, client_ecdsa_config));
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_signature_algorithm_select(conn),
                        S2N_ERR_NO_VALID_SIGNATURE_SCHEME);

                /* Succeeds for config with rsa cert */
                EXPECT_SUCCESS(s2n_connection_set_config(conn, client_rsa_config));
                EXPECT_OK(s2n_signature_algorithm_select(conn));
            };

            /* Test: no ecdsa certs */
            {
                const struct s2n_signature_scheme *scheme = &s2n_ecdsa_sha384;

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                conn->actual_protocol_version = S2N_TLS12;
                conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        &scheme, 1));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        &scheme, 1));

                /* Fails for default config with no certs */
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_signature_algorithm_select(conn),
                        S2N_ERR_NO_VALID_SIGNATURE_SCHEME);

                /* Fails for config with rsa cert */
                EXPECT_SUCCESS(s2n_connection_set_config(conn, client_rsa_config));
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_signature_algorithm_select(conn),
                        S2N_ERR_NO_VALID_SIGNATURE_SCHEME);

                /* Succeeds for config with ecdsa cert */
                EXPECT_SUCCESS(s2n_connection_set_config(conn, client_ecdsa_config));
                EXPECT_OK(s2n_signature_algorithm_select(conn));
            };

            /* Test: ecdsa cert exists, but for wrong curve.
             *
             * This is enforced for TLS1.3, where curves are specified by the
             * signature schemes, but not for TLS1.2 where the supported_groups
             * extension is used instead. See https://github.com/aws/s2n-tls/issues/4274
             */
            {
                const struct s2n_signature_scheme *ecdsa384 = &s2n_ecdsa_sha384;
                const struct s2n_signature_scheme *ecdsa256 = &s2n_ecdsa_sha256;

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                conn->actual_protocol_version = S2N_TLS13;
                conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
                EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

                struct s2n_local_sig_schemes_context local_context = { 0 };

                /* Fails with wrong curve (256) */
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        &ecdsa256, 1));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        &ecdsa256, 1));
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_signature_algorithm_select(conn),
                        S2N_ERR_NO_VALID_SIGNATURE_SCHEME);

                /* Succeeds with right curve (384) */
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        &ecdsa384, 1));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        &ecdsa384, 1));
                EXPECT_OK(s2n_signature_algorithm_select(conn));
            };
        };

        /* Test: skip invalid schemes and choose a less preferred scheme */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, client_ecdsa_config));

            const struct s2n_signature_scheme *expected = &s2n_ecdsa_sha384;
            const struct s2n_signature_scheme *schemes[] = {
                /* No RSA certificates */
                &s2n_rsa_pss_rsae_sha256,
                &s2n_rsa_pss_pss_sha256,
                &s2n_rsa_pkcs1_sha256,
                /* Only valid for TLS1.2 */
                &s2n_ecdsa_sha224,
                /* Wrong curve */
                &s2n_ecdsa_sha256,
                expected
            };

            struct s2n_local_sig_schemes_context local_context = { 0 };
            EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                    schemes, s2n_array_len(schemes)));
            EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                    schemes, s2n_array_len(schemes)));

            EXPECT_OK(s2n_signature_algorithm_select(conn));
            EXPECT_EQUAL(conn->handshake_params.client_cert_sig_scheme, expected);
        };

        /* Test: skip schemes not offered by the peer and choose a less preferred scheme */
        {
            const struct s2n_signature_scheme *expected = &s2n_rsa_pkcs1_sha256;
            const struct s2n_signature_scheme *peer_schemes[] = {
                expected
            };
            const struct s2n_signature_scheme *local_schemes[] = {
                &s2n_rsa_pss_rsae_sha256,
                &s2n_rsa_pss_pss_sha256,
                &s2n_ecdsa_sha384,
                expected,
            };

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure->cipher_suite = RSA_CIPHER_SUITE;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

            struct s2n_local_sig_schemes_context local_context = { 0 };
            EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                    local_schemes, s2n_array_len(local_schemes)));
            EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                    peer_schemes, s2n_array_len(peer_schemes)));

            EXPECT_OK(s2n_signature_algorithm_select(conn));
            EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, expected);
        };

        /* Test: no schemes offered by the peer */
        {
            const struct s2n_signature_scheme *ecdsa_not_default = &s2n_ecdsa_sha384;
            const struct s2n_signature_scheme *rsa_not_default = &s2n_rsa_pkcs1_sha256;

            /* Test: defaults allowed by security policy */
            {
                /* We should need to skip valid non-default schemes to choose the defaults */
                const struct s2n_signature_scheme *schemes_with_defaults[] = {
                    ecdsa_not_default,
                    rsa_not_default,
                    rsa_default,
                    ecdsa_default
                };

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        schemes_with_defaults, s2n_array_len(schemes_with_defaults)));

                /* TLS1.2 with ECDSA chooses ECDSA default */
                conn->actual_protocol_version = S2N_TLS12;
                conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, ecdsa_default);

                /* TLS1.2 with RSA chooses RSA default */
                conn->actual_protocol_version = S2N_TLS12;
                conn->secure->cipher_suite = RSA_CIPHER_SUITE;
                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, rsa_default);

                /* TLS1.3 never chooses the defaults */
                conn->actual_protocol_version = S2N_TLS13;
                conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, ecdsa_not_default);
            }

            /* Test: defaults not allowed by security policy */
            {
                const struct s2n_signature_scheme *schemes_without_defaults[] = {
                    ecdsa_not_default,
                    rsa_not_default,
                    /* Add some more, less preferred non-defaults.
                     * We only choose the most preferred though. */
                    &s2n_ecdsa_sha512,
                    &s2n_ecdsa_sha256,
                    &s2n_rsa_pss_rsae_sha384,
                };

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        schemes_without_defaults, s2n_array_len(schemes_without_defaults)));

                /* TLS1.2 with ECDSA does not choose default */
                conn->actual_protocol_version = S2N_TLS12;
                conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, ecdsa_not_default);

                /* TLS1.2 with RSA does not choose default */
                conn->actual_protocol_version = S2N_TLS12;
                conn->secure->cipher_suite = RSA_CIPHER_SUITE;
                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, rsa_not_default);

                /* TLS1.3 never chooses the defaults */
                conn->actual_protocol_version = S2N_TLS13;
                conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, ecdsa_not_default);
            };

            /* Test: skip invalid fallback candidates to choose valid one */
            {
                const struct s2n_signature_scheme *expected = &s2n_ecdsa_sha384;
                const struct s2n_signature_scheme *schemes[] = {
                    /* No RSA certificates */
                    &s2n_rsa_pss_rsae_sha256,
                    &s2n_rsa_pss_pss_sha256,
                    &s2n_rsa_pkcs1_sha256,
                    /* Only valid for TLS1.2 */
                    &s2n_ecdsa_sha224,
                    /* Wrong curve */
                    &s2n_ecdsa_sha256,
                    expected
                };

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                conn->actual_protocol_version = S2N_TLS13;
                conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
                EXPECT_SUCCESS(s2n_connection_set_config(conn, client_ecdsa_config));

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        schemes, s2n_array_len(schemes)));
                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.client_cert_sig_scheme, expected);
            };
        };

        /* Test: No valid schemes offered by the peer.
         *
         * s2n-tls deviates from the RFC here by applying the same logic as if
         * the peer offered no signature schemes at all.
         */
        {
            const struct s2n_signature_scheme *ecdsa_not_default = &s2n_ecdsa_sha384;
            const struct s2n_signature_scheme *rsa_not_default = &s2n_rsa_pss_rsae_sha256;

            /* Test: TLS1.2 chooses defaults */
            {
                /* TLS1.2 does not support rsa-pss certs */
                const struct s2n_signature_scheme *invalid_scheme = &s2n_rsa_pss_pss_sha256;

                /* We should need to skip valid non-default schemes to choose the defaults */
                const struct s2n_signature_scheme *local_schemes[] = {
                    invalid_scheme,
                    ecdsa_not_default,
                    rsa_not_default,
                    rsa_default,
                    ecdsa_default
                };
                const struct s2n_signature_scheme *peer_schemes[] = {
                    invalid_scheme
                };

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        local_schemes, s2n_array_len(local_schemes)));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        peer_schemes, s2n_array_len(peer_schemes)));

                /* ECDSA */
                conn->actual_protocol_version = S2N_TLS12;
                conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, ecdsa_default);

                /* ECDSA */
                conn->actual_protocol_version = S2N_TLS12;
                conn->secure->cipher_suite = RSA_CIPHER_SUITE;
                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, rsa_default);
            };

            /* Test: TLS1.3 chooses most preferred valid */
            {
                /* We should need to skip valid non-default schemes to choose the defaults */
                const struct s2n_signature_scheme *local_schemes[] = {
                    &s2n_ecdsa_sha224,
                    rsa_default,
                    ecdsa_default,
                    ecdsa_not_default
                };
                const struct s2n_signature_scheme *peer_schemes[] = {
                    &s2n_ecdsa_sha224,
                    /* TLS1.3 does not support the TLS1.2 defaults */
                    rsa_default,
                    ecdsa_default
                };

                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                conn->actual_protocol_version = S2N_TLS13;
                conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
                EXPECT_SUCCESS(s2n_connection_set_config(conn, server_config));

                struct s2n_local_sig_schemes_context local_context = { 0 };
                EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                        local_schemes, s2n_array_len(local_schemes)));
                EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                        peer_schemes, s2n_array_len(peer_schemes)));

                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, ecdsa_not_default);
            };
        };
    };

    /* s2n_signature_algorithm_recv */
    {
        struct s2n_security_policy test_security_policy = *s2n_fetch_default_config()->security_policy;
        test_security_policy.signature_preferences = &test_preferences;

        /* Test: successfully choose valid server signature */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            conn->security_policy_override = &test_security_policy;
            conn->actual_protocol_version = S2N_TLS12;

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&input, s2n_rsa_pkcs1_sha256.iana_value));

            EXPECT_OK(s2n_signature_algorithm_recv(conn, &input));
            EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, &s2n_rsa_pkcs1_sha256);
        };

        /* Test: successfully choose valid client signature */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->security_policy_override = &test_security_policy;
            conn->actual_protocol_version = S2N_TLS12;

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&input, s2n_rsa_pkcs1_sha256.iana_value));

            EXPECT_OK(s2n_signature_algorithm_recv(conn, &input));
            EXPECT_EQUAL(conn->handshake_params.client_cert_sig_scheme, &s2n_rsa_pkcs1_sha256);
        };

        /* Test: algorithm not included in message */
        {
            struct s2n_stuffer empty = { 0 };

            /* Algorithm must be provided if >= TLS1.2 */
            {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                conn->security_policy_override = &test_security_policy;
                conn->actual_protocol_version = S2N_TLS12;

                conn->secure->cipher_suite = RSA_CIPHER_SUITE;
                EXPECT_ERROR_WITH_ERRNO(s2n_signature_algorithm_recv(conn, &empty),
                        S2N_ERR_BAD_MESSAGE);
            }

            /* Client chooses default based on cipher suite */
            {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                conn->security_policy_override = &test_security_policy;
                conn->actual_protocol_version = S2N_TLS11;

                conn->secure->cipher_suite = RSA_CIPHER_SUITE;
                EXPECT_OK(s2n_signature_algorithm_recv(conn, &empty));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, &s2n_rsa_pkcs1_md5_sha1);

                conn->secure->cipher_suite = ECDSA_CIPHER_SUITE;
                EXPECT_OK(s2n_signature_algorithm_recv(conn, &empty));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, &s2n_ecdsa_sha1);
            };

            /* Server chooses default based on client cert type */
            {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                conn->security_policy_override = &test_security_policy;
                conn->actual_protocol_version = S2N_TLS11;

                conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_RSA;
                EXPECT_OK(s2n_signature_algorithm_recv(conn, &empty));
                EXPECT_EQUAL(conn->handshake_params.client_cert_sig_scheme, &s2n_rsa_pkcs1_md5_sha1);

                conn->handshake_params.client_cert_pkey_type = S2N_PKEY_TYPE_ECDSA;
                EXPECT_OK(s2n_signature_algorithm_recv(conn, &empty));
                EXPECT_EQUAL(conn->handshake_params.client_cert_sig_scheme, &s2n_ecdsa_sha1);
            };
        };

        /* Test: don't negotiate signature scheme not allowed by security policy */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            const struct s2n_signature_scheme *const test_schemes[] = {
                &s2n_rsa_pkcs1_sha256,
                &s2n_ecdsa_sha256,
                /* Include legacy defaults to ensure no exceptions made for defaults */
                &s2n_rsa_pkcs1_md5_sha1,
                &s2n_ecdsa_sha1,
            };
            const struct s2n_signature_scheme *const supported_schemes[] = {
                &s2n_ecdsa_sha384,
            };

            struct s2n_security_policy test_policy = test_security_policy;
            struct s2n_signature_preferences test_prefs = {
                .signature_schemes = supported_schemes,
                .count = s2n_array_len(supported_schemes),
            };
            test_policy.signature_preferences = &test_prefs;

            struct s2n_security_policy control_policy = test_security_policy;
            struct s2n_signature_preferences control_prefs = {
                .signature_schemes = test_schemes,
                .count = s2n_array_len(test_schemes),
            };
            control_policy.signature_preferences = &control_prefs;

            /* Signature algorithms not allowed by policy rejected */
            conn->security_policy_override = &test_policy;
            for (size_t i = 0; i < s2n_array_len(test_schemes); i++) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint16(&input, test_schemes[i]->iana_value));
                EXPECT_ERROR_WITH_ERRNO(s2n_signature_algorithm_recv(conn, &input),
                        S2N_ERR_INVALID_SIGNATURE_SCHEME);
            }

            /* Signature algorithms allowed by policy accepted */
            conn->security_policy_override = &control_policy;
            for (size_t i = 0; i < s2n_array_len(test_schemes); i++) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint16(&input, test_schemes[i]->iana_value));
                EXPECT_OK(s2n_signature_algorithm_recv(conn, &input));
            }
        };

        /* Test: don't negotiate invalid signatures (protocol too high) */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            conn->security_policy_override = &test_security_policy;

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&input, s2n_rsa_pkcs1_sha224.iana_value));
            EXPECT_OK(s2n_signature_algorithm_recv(conn, &input));
            EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, &s2n_rsa_pkcs1_sha224);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&input, s2n_rsa_pkcs1_sha224.iana_value));
            EXPECT_ERROR_WITH_ERRNO(s2n_signature_algorithm_recv(conn, &input),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
        };
    };

    /* Test: Ensure that the maximum number of permitted signature schemes can be received. */
    const uint16_t max_sig_schemes = TLS_SIGNATURE_SCHEME_LIST_MAX_LEN;
    for (uint16_t count = max_sig_schemes - 1; count <= max_sig_schemes + 1; count++) {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

        uint16_t sig_scheme_list_size = count * TLS_SIGNATURE_SCHEME_LEN;
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&input, sig_scheme_list_size));
        for (size_t i = 0; i < count; i++) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&input, s2n_rsa_pkcs1_sha256.iana_value));
        }

        int ret = s2n_recv_supported_sig_scheme_list(&input, &conn->handshake_params.peer_sig_scheme_list);
        if (count <= max_sig_schemes) {
            EXPECT_SUCCESS(ret);
        } else {
            EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_TOO_MANY_SIGNATURE_SCHEMES);
        }
    }

    /* Test: send and receive default signature preferences */
    for (size_t i = S2N_TLS10; i < S2N_TLS13; i++) {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        conn->actual_protocol_version = i;

        DEFER_CLEANUP(struct s2n_stuffer result = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&result, 0));
        EXPECT_OK(s2n_signature_algorithms_supported_list_send(conn, &result));

        struct s2n_sig_scheme_list signatures = { 0 };
        EXPECT_SUCCESS(s2n_recv_supported_sig_scheme_list(&result, &signatures));
        EXPECT_EQUAL(s2n_stuffer_data_available(&result), 0);

        /* Verify no duplicates - some preferences contain duplicates, but only
         * one should be valid at a time. */
        uint16_t iana = 0, other_iana = 0;
        for (size_t a = 0; a < signatures.len; a++) {
            iana = signatures.iana_list[a];
            for (int b = 0; b < signatures.len; b++) {
                if (a == b) {
                    continue;
                }
                other_iana = signatures.iana_list[b];
                EXPECT_NOT_EQUAL(iana, other_iana);
            }
        }
    };

    /* Test: libcrypto may not support PSS signatures */
    {
        const struct s2n_signature_scheme *const pss_test_signature_schemes[] = {
            &s2n_rsa_pss_rsae_sha256,
            &s2n_rsa_pss_pss_sha256,
        };

        const struct s2n_signature_preferences pss_test_preferences = {
            .count = 2,
            .signature_schemes = pss_test_signature_schemes,
        };

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_cert_chain));

        struct s2n_security_policy test_security_policy = *s2n_fetch_default_config()->security_policy;
        test_security_policy.signature_preferences = &pss_test_preferences,
        config->security_policy = &test_security_policy;

        /* Do not offer PSS signatures schemes if unsupported:
         * s2n_signature_algorithms_supported_list_send + PSS */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            DEFER_CLEANUP(struct s2n_stuffer result = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&result, 0));
            EXPECT_OK(s2n_signature_algorithms_supported_list_send(conn, &result));

            uint16_t size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&result, &size));
            EXPECT_EQUAL(size, s2n_stuffer_data_available(&result));
            if (s2n_is_rsa_pss_certs_supported()) {
                EXPECT_EQUAL(size, 2 * sizeof(uint16_t));
            } else if (s2n_is_rsa_pss_signing_supported()) {
                EXPECT_EQUAL(size, 1 * sizeof(uint16_t));
            } else {
                EXPECT_EQUAL(size, 0);
            }
        };

        /* Do not accept a PSS signature scheme if unsupported:
         * s2n_signature_algorithm_recv + PSS */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&input, s2n_rsa_pss_rsae_sha256.iana_value));

            if (s2n_is_rsa_pss_signing_supported()) {
                EXPECT_OK(s2n_signature_algorithm_recv(conn, &input));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme, &s2n_rsa_pss_rsae_sha256);
            } else {
                EXPECT_ERROR_WITH_ERRNO(s2n_signature_algorithm_recv(conn, &input),
                        S2N_ERR_INVALID_SIGNATURE_SCHEME);
            }
        };

        /* Do not choose a PSS signature scheme if unsupported:
         * s2n_signature_algorithm_select + PSS */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            const struct s2n_signature_scheme *schemes[] = { &s2n_rsa_pss_rsae_sha256 };
            EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                    schemes, s2n_array_len(schemes)));

            if (s2n_is_rsa_pss_signing_supported()) {
                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.client_cert_sig_scheme,
                        &s2n_rsa_pss_rsae_sha256);
            } else {
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_signature_algorithm_select(conn),
                        S2N_ERR_NO_VALID_SIGNATURE_SCHEME);
            }
        };

        /* Fallback to a PSS scheme if only PKCS1 offered:
         * s2n_signature_algorithm_select + PSS
         */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            conn->secure->cipher_suite = TLS13_CIPHER_SUITE;
            conn->actual_protocol_version = S2N_TLS13;

            /* Invalid (PKCS1 not allowed by TLS1.3) */
            const struct s2n_signature_scheme *peer_schemes[] = { &s2n_rsa_pkcs1_sha224 };
            EXPECT_OK(s2n_test_set_peer_sig_schemes(&conn->handshake_params.peer_sig_scheme_list,
                    peer_schemes, s2n_array_len(peer_schemes)));

            /* Both PKCS1 and PSS supported */
            const struct s2n_signature_scheme *local_schemes[] = {
                &s2n_rsa_pkcs1_sha224,
                &s2n_rsa_pss_rsae_sha256,
                &s2n_rsa_pss_rsae_sha384,
            };
            struct s2n_local_sig_schemes_context local_context = { 0 };
            EXPECT_OK(s2n_test_set_local_sig_schemes(conn, &local_context,
                    local_schemes, s2n_array_len(local_schemes)));

            /* No fallback if PSS not valid either (no RSA cert) */
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_signature_algorithm_select(conn),
                    S2N_ERR_NO_VALID_SIGNATURE_SCHEME);

            /* Set the RSA cert, making our PSS option valid */
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            /* Fallback to preferred PSS scheme if supported */
            if (s2n_is_rsa_pss_signing_supported()) {
                EXPECT_OK(s2n_signature_algorithm_select(conn));
                EXPECT_EQUAL(conn->handshake_params.server_cert_sig_scheme,
                        &s2n_rsa_pss_rsae_sha256);
            } else {
                EXPECT_ERROR_WITH_ERRNO(
                        s2n_signature_algorithm_select(conn),
                        S2N_ERR_NO_VALID_SIGNATURE_SCHEME);
            }
        };
    };

    /* Self-Talk tests: default signature schemes */
    {
        const struct s2n_signature_scheme *const default_schemes[] = {
            &s2n_rsa_pkcs1_sha1,
            &s2n_ecdsa_sha1
        };

        const struct s2n_signature_scheme *const sha256_schemes[] = {
            &s2n_rsa_pkcs1_sha256,
            &s2n_ecdsa_sha256
        };

        const struct s2n_signature_scheme *const sha384_schemes[] = {
            &s2n_rsa_pkcs1_sha384,
            &s2n_ecdsa_sha384
        };

        const struct s2n_signature_preferences defaults_preferences = {
            .count = s2n_array_len(default_schemes),
            .signature_schemes = default_schemes,
        };

        const struct s2n_signature_preferences sha256_preferences = {
            .count = s2n_array_len(sha256_schemes),
            .signature_schemes = sha256_schemes,
        };
        for (size_t i = 0; i < sha256_preferences.count; i++) {
            for (size_t j = 0; j < defaults_preferences.count; j++) {
                EXPECT_NOT_EQUAL(sha256_preferences.signature_schemes[i]->iana_value,
                        defaults_preferences.signature_schemes[j]->iana_value);
            }
        }

        const struct s2n_signature_preferences sha384_preferences = {
            .count = s2n_array_len(sha384_schemes),
            .signature_schemes = sha384_schemes,
        };
        for (size_t i = 0; i < sha384_preferences.count; i++) {
            for (size_t j = 0; j < defaults_preferences.count; j++) {
                EXPECT_NOT_EQUAL(sha384_preferences.signature_schemes[i]->iana_value,
                        defaults_preferences.signature_schemes[j]->iana_value);
            }
        }

        /* The policy needs to negotiate TLS1.2 and forward secret kex */
        struct s2n_security_policy defaults_policy = security_policy_20190214;
        defaults_policy.signature_preferences = &defaults_preferences;
        struct s2n_security_policy sha256_policy = security_policy_20190214;
        sha256_policy.signature_preferences = &sha256_preferences;
        struct s2n_security_policy sha384_policy = security_policy_20190214;
        sha384_policy.signature_preferences = &sha384_preferences;

        /* Self-Talk test: client and server can negotiate without any defaults */
        for (size_t cert_i = 0; cert_i < s2n_array_len(certs); cert_i++) {
            /* Setup config */
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, certs[cert_i]));

            /* Setup connections */
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            /* Create nonblocking pipes */
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Client and server security policies should match but include no defaults */
            client_conn->security_policy_override = &sha256_policy;
            server_conn->security_policy_override = &sha256_policy;

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        };

        /* Self-Talk test: server does not fallback to unsupported defaults */
        for (size_t cert_i = 0; cert_i < s2n_array_len(certs); cert_i++) {
            /* Setup config */
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, certs[cert_i]));

            /* Setup connections */
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

            /* Create nonblocking pipes */
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Client and server security policies should have no signature schemes
             * in common, and not include the default signature schemes.
             */
            client_conn->security_policy_override = &sha256_policy;
            server_conn->security_policy_override = &sha384_policy;

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        };

        /* Self-Talk test: client does not accept unsupported defaults */
        for (size_t cert_i = 0; cert_i < s2n_array_len(certs); cert_i++) {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, certs[cert_i]));

            /* Setup connections */
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

            /* Create nonblocking pipes */
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Client and server security policies should have no signature schemes in common.
             * Server should include the default policies.
             */
            client_conn->security_policy_override = &sha256_policy;
            server_conn->security_policy_override = &defaults_policy;

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_INVALID_SIGNATURE_SCHEME);
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        };
    };

    EXPECT_SUCCESS(s2n_reset_tls13_in_test());

    /* Self-Talk test: In TLS1.3, the ECDSA signature scheme curve must match
     * the ECDSA certificate curve.
     *
     * But:
     * Signature scheme curves do NOT have to match certificate curves in TLS1.2.
     * Signature scheme curves do NOT have to match the ECDHE curve.
     * Signature scheme hashes do NOT have to match PRF hashes.
     */
    if (s2n_is_tls13_fully_supported()) {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));

        /* Certificate uses p521 */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_p521_chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_p521_chain,
                S2N_ECDSA_P512_CERT_CHAIN, S2N_ECDSA_P512_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_p521_chain));

        /* Cipher should use SHA256 for PRF */
        struct s2n_cipher_suite *cipher_suite_tls13 = &s2n_tls13_aes_128_gcm_sha256;
        struct s2n_cipher_suite *cipher_suite_tls12 = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
        struct s2n_cipher_preferences cipher_prefs = {
            .count = 1,
            .suites = NULL
        };
        /* TLS1.2 prefers SHA224 for signatures.
         * TLS1.3 has to use SHA512 to match the certificate.
         * Include another valid TLS1.3 option (SHA256) to verify SHA512 is still chosen.
         */
        const struct s2n_signature_scheme *sig_schemes[] = {
            &s2n_ecdsa_sha224,
            &s2n_ecdsa_sha256,
            &s2n_ecdsa_sha512
        };
        struct s2n_signature_preferences sig_prefs = {
            .count = s2n_array_len(sig_schemes),
            .signature_schemes = sig_schemes
        };
        /* Key exchange prefers SHA384 */
        const struct s2n_ecc_named_curve *curves[] = {
            &s2n_ecc_curve_secp384r1,
            &s2n_ecc_curve_secp521r1
        };
        struct s2n_ecc_preferences ecc_prefs = {
            .count = s2n_array_len(curves),
            .ecc_curves = curves
        };
        struct s2n_security_policy policy = security_policy_20230317;
        policy.cipher_preferences = &cipher_prefs;
        policy.signature_preferences = &sig_prefs;
        policy.ecc_preferences = &ecc_prefs;
        config->security_policy = &policy;

        for (uint8_t version = S2N_TLS12; version <= S2N_TLS13; version++) {
            if (version >= S2N_TLS13) {
                cipher_prefs.suites = &cipher_suite_tls13;
            } else {
                cipher_prefs.suites = &cipher_suite_tls12;
            }

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client, config));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
            EXPECT_EQUAL(client->actual_protocol_version, version);
            EXPECT_EQUAL(server->actual_protocol_version, version);

            if (version >= S2N_TLS13) {
                /* TLS1.3 sig scheme does have to match certificate: 512 */
                EXPECT_EQUAL(server->handshake_params.server_cert_sig_scheme, &s2n_ecdsa_sha512);
            } else {
                /* TLS1.2 sig scheme does not have to match certificate: 224 */
                EXPECT_NOT_EQUAL(server->handshake_params.server_cert_sig_scheme, &s2n_ecdsa_sha512);
                EXPECT_EQUAL(server->handshake_params.server_cert_sig_scheme, &s2n_ecdsa_sha224);
            }

            /* PRF does not have to match certificate or sig scheme: 256 */
            EXPECT_NOT_EQUAL(server->secure->cipher_suite->prf_alg, S2N_HMAC_SHA512);
            EXPECT_EQUAL(server->secure->cipher_suite->prf_alg, S2N_HMAC_SHA256);

            /* KEX does not have to match certificate or sig scheme or PRF: 384 */
            EXPECT_NOT_EQUAL(server->kex_params.server_ecc_evp_params.negotiated_curve,
                    &s2n_ecc_curve_secp521r1);
            EXPECT_EQUAL(server->kex_params.server_ecc_evp_params.negotiated_curve,
                    &s2n_ecc_curve_secp384r1);
        }
    }

    END_TEST();

    return 0;
}
