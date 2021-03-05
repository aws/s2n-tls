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
#include "tls/s2n_kem_preferences.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_ecc_preferences.h"
#include "s2n.h"
#include "tls/s2n_handshake.h"
#include "pq-crypto/s2n_pq.h"

/* Include C file directly to access static functions */
#include "tls/s2n_handshake_io.c"

int s2n_test_tls13_pq_handshake(const struct s2n_security_policy *client_sec_policy,
        const struct s2n_security_policy *server_sec_policy, const struct s2n_kem_group *expected_kem_group,
        const struct s2n_ecc_named_curve *expected_curve, bool should_send_ec_shares, bool hrr_expected) {
    /* XOR check: can expect to negotiate either a KEM group, or a classic EC curve, but not both/neither */
    POSIX_ENSURE((expected_kem_group == NULL) != (expected_curve == NULL), S2N_ERR_SAFETY);

    /* Set up connections */
    struct s2n_connection *client_conn = NULL, *server_conn = NULL;
    POSIX_ENSURE_REF(client_conn = s2n_connection_new(S2N_CLIENT));
    POSIX_ENSURE_REF(server_conn = s2n_connection_new(S2N_SERVER));

    struct s2n_config *client_config = NULL, *server_config = NULL;
    POSIX_ENSURE_REF(client_config = s2n_config_new());
    POSIX_ENSURE_REF(server_config = s2n_config_new());

    char cert_chain[S2N_MAX_TEST_PEM_SIZE] = { 0 }, private_key[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    struct s2n_cert_chain_and_key *chain_and_key = NULL;
    POSIX_ENSURE_REF(chain_and_key = s2n_cert_chain_and_key_new());
    POSIX_GUARD(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    POSIX_GUARD(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
    POSIX_GUARD(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
    POSIX_GUARD(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
    POSIX_GUARD(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

    POSIX_GUARD(s2n_connection_set_config(client_conn, client_config));
    POSIX_GUARD(s2n_connection_set_config(server_conn, server_config));

    struct s2n_stuffer client_to_server = { 0 }, server_to_client = { 0 };
    POSIX_GUARD(s2n_stuffer_growable_alloc(&client_to_server, 2048));
    POSIX_GUARD(s2n_stuffer_growable_alloc(&server_to_client, 2048));

    POSIX_GUARD(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));
    POSIX_GUARD(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));

    client_conn->security_policy_override = client_sec_policy;
    server_conn->security_policy_override = server_sec_policy;

    /* Client sends ClientHello */
    if (!should_send_ec_shares) {
        /* In certain tests, we do not want to send any classic EC shares in order to force
         * the server to choose PQ with HRR for negotiation. */
        POSIX_GUARD(s2n_connection_set_keyshare_by_name_for_testing(client_conn, "none"));
    }
    POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(client_conn), CLIENT_HELLO);
    POSIX_GUARD(s2n_handshake_write_io(client_conn));

    POSIX_ENSURE_EQ(client_conn->actual_protocol_version, S2N_TLS13);
    POSIX_ENSURE_EQ(server_conn->actual_protocol_version, 0); /* Won't get set until after server reads ClientHello */
    POSIX_ENSURE_EQ(client_conn->handshake.handshake_type,  INITIAL);

    /* Server reads ClientHello */
    POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
    POSIX_GUARD(s2n_handshake_read_io(server_conn));

    POSIX_ENSURE_EQ(server_conn->actual_protocol_version, S2N_TLS13); /* Server is now on TLS13 */

    /* Assert that the server chose the correct group */
    if (expected_kem_group) {
        POSIX_ENSURE_EQ(expected_kem_group, server_conn->secure.server_kem_group_params.kem_group);
        POSIX_ENSURE_EQ(expected_kem_group->kem, server_conn->secure.server_kem_group_params.kem_params.kem);
        POSIX_ENSURE_EQ(expected_kem_group->curve, server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        POSIX_ENSURE_EQ(NULL, server_conn->secure.server_ecc_evp_params.negotiated_curve);
    } else {
        POSIX_ENSURE_EQ(NULL, server_conn->secure.server_kem_group_params.kem_group);
        POSIX_ENSURE_EQ(NULL, server_conn->secure.server_kem_group_params.kem_params.kem);
        POSIX_ENSURE_EQ(NULL, server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        POSIX_ENSURE_EQ(expected_curve, server_conn->secure.server_ecc_evp_params.negotiated_curve);
    }

    /* Server sends ServerHello or HRR */
    POSIX_GUARD(s2n_conn_set_handshake_type(server_conn));
    if (hrr_expected) {
        POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(server_conn), HELLO_RETRY_MSG);
    } else {
        POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(server_conn), SERVER_HELLO);
    }
    POSIX_GUARD(s2n_handshake_write_io(server_conn));

    /* Server sends CCS */
    POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(server_conn), SERVER_CHANGE_CIPHER_SPEC);
    POSIX_GUARD(s2n_handshake_write_io(server_conn));

    if (hrr_expected) {
        /* Client reads HRR */
        POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
        POSIX_GUARD(s2n_handshake_read_io(client_conn));
        POSIX_GUARD(s2n_conn_set_handshake_type(client_conn));
        POSIX_ENSURE_NE(0, client_conn->handshake.handshake_type & HELLO_RETRY_REQUEST);

        /* Client reads CCS */
        POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(client_conn), CLIENT_CHANGE_CIPHER_SPEC);
        POSIX_GUARD(s2n_handshake_read_io(client_conn));

        /* Client sends CCS and new ClientHello */
        POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(client_conn), CLIENT_CHANGE_CIPHER_SPEC);
        POSIX_GUARD(s2n_handshake_write_io(client_conn));
        POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(client_conn), CLIENT_HELLO);
        POSIX_GUARD(s2n_handshake_write_io(client_conn));

        /* Server reads CCS (doesn't change state machine) */
        POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
        POSIX_GUARD(s2n_handshake_read_io(server_conn));

        /* Server reads new ClientHello */
        POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
        POSIX_GUARD(s2n_handshake_read_io(server_conn));

        /* Server sends ServerHello */
        POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(server_conn), SERVER_HELLO);
        POSIX_GUARD(s2n_handshake_write_io(server_conn));
    }

    /* Client reads ServerHello */
    POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
    POSIX_GUARD(s2n_handshake_read_io(client_conn));

    /* We've gotten far enough in the handshake that both client and server should have
     * derived the shared secrets, so we don't send/receive any more messages. */

    /* Assert that the correct group was negotiated (we re-check the server group to assert that
     * nothing unexpected changed between then and now while e.g. processing HRR) */
    if (expected_kem_group) {
        POSIX_ENSURE_EQ(expected_kem_group, client_conn->secure.server_kem_group_params.kem_group);
        POSIX_ENSURE_EQ(expected_kem_group->kem, client_conn->secure.server_kem_group_params.kem_params.kem);
        POSIX_ENSURE_EQ(expected_kem_group->curve, client_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        POSIX_ENSURE_EQ(NULL, client_conn->secure.server_ecc_evp_params.negotiated_curve);

        POSIX_ENSURE_EQ(expected_kem_group, server_conn->secure.server_kem_group_params.kem_group);
        POSIX_ENSURE_EQ(expected_kem_group->kem, server_conn->secure.server_kem_group_params.kem_params.kem);
        POSIX_ENSURE_EQ(expected_kem_group->curve, server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        POSIX_ENSURE_EQ(NULL, server_conn->secure.server_ecc_evp_params.negotiated_curve);
    } else {
        POSIX_ENSURE_EQ(NULL, client_conn->secure.server_kem_group_params.kem_group);
        POSIX_ENSURE_EQ(NULL, client_conn->secure.server_kem_group_params.kem_params.kem);
        POSIX_ENSURE_EQ(NULL, client_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        POSIX_ENSURE_EQ(expected_curve, client_conn->secure.server_ecc_evp_params.negotiated_curve);

        POSIX_ENSURE_EQ(NULL, server_conn->secure.server_kem_group_params.kem_group);
        POSIX_ENSURE_EQ(NULL, server_conn->secure.server_kem_group_params.kem_params.kem);
        POSIX_ENSURE_EQ(NULL, server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        POSIX_ENSURE_EQ(expected_curve, server_conn->secure.server_ecc_evp_params.negotiated_curve);
    }

    /* Verify basic properties of secrets */
    s2n_tls13_connection_keys(server_secrets, server_conn);
    s2n_tls13_connection_keys(client_secrets, client_conn);
    POSIX_ENSURE_REF(server_secrets.extract_secret.data);
    POSIX_ENSURE_REF(server_secrets.derive_secret.data);
    POSIX_ENSURE_REF(client_secrets.extract_secret.data);
    POSIX_ENSURE_REF(client_secrets.derive_secret.data);
    POSIX_ENSURE_EQ(server_conn->secure.cipher_suite, client_conn->secure.cipher_suite);
    if (server_conn->secure.cipher_suite == &s2n_tls13_aes_256_gcm_sha384) {
        POSIX_ENSURE_EQ(server_secrets.size, 48);
        POSIX_ENSURE_EQ(client_secrets.size, 48);
    } else {
        POSIX_ENSURE_EQ(server_secrets.size, 32);
        POSIX_ENSURE_EQ(client_secrets.size, 32);
    }

    /* Verify secrets aren't just zero'ed memory */
    uint8_t all_zeros[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
    POSIX_CHECKED_MEMSET((void *)all_zeros, 0, S2N_TLS13_SECRET_MAX_LEN);
    POSIX_ENSURE_NE(0, memcmp(all_zeros, client_secrets.derive_secret.data, client_secrets.derive_secret.size));
    POSIX_ENSURE_NE(0, memcmp(all_zeros, client_secrets.extract_secret.data, client_secrets.extract_secret.size));
    POSIX_ENSURE_NE(0, memcmp(all_zeros, server_secrets.derive_secret.data, server_secrets.derive_secret.size));
    POSIX_ENSURE_NE(0, memcmp(all_zeros, server_secrets.extract_secret.data, server_secrets.extract_secret.size));

    /* Verify client and server secrets are equal to each other */
    POSIX_ENSURE_EQ(server_secrets.derive_secret.size, client_secrets.derive_secret.size);
    POSIX_ENSURE_EQ(0, memcmp(server_secrets.derive_secret.data, client_secrets.derive_secret.data, client_secrets.derive_secret.size));
    POSIX_ENSURE_EQ(server_secrets.extract_secret.size, client_secrets.extract_secret.size);
    POSIX_ENSURE_EQ(0, memcmp(server_secrets.extract_secret.data, client_secrets.extract_secret.data, client_secrets.extract_secret.size));

    /* Clean up */
    POSIX_GUARD(s2n_stuffer_free(&client_to_server));
    POSIX_GUARD(s2n_stuffer_free(&server_to_client));

    POSIX_GUARD(s2n_connection_free(client_conn));
    POSIX_GUARD(s2n_connection_free(server_conn));

    POSIX_GUARD(s2n_cert_chain_and_key_free(chain_and_key));
    POSIX_GUARD(s2n_config_free(server_config));
    POSIX_GUARD(s2n_config_free(client_config));

    return S2N_SUCCESS;
}

int main() {
    BEGIN_TEST();

    /* Additional KEM preferences/security policies to test against. These policies can only be used
     * as the server's policy in this test: when generating the ClientHello, the client relies on
     * the security_policy_selection[] array (in s2n_security_policies.c) to determine if it should
     * write the supported_groups extension. Because these unofficial policies don't exist in that
     * array, the supported_groups extension won't get sent and the handshake won't complete as expected. */

    /* Kyber */
    const struct s2n_kem_group *kyber_test_groups[] = {
#if EVP_APIS_SUPPORTED
            &s2n_x25519_kyber_512_r2,
#endif
            &s2n_secp256r1_kyber_512_r2,
    };

    const struct s2n_kem_preferences kyber_test_prefs = {
            .kem_count = 0,
            .kems = NULL,
            .tls13_kem_group_count = s2n_array_len(kyber_test_groups),
            .tls13_kem_groups = kyber_test_groups,
    };

    const struct s2n_security_policy kyber_test_policy = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &cipher_preferences_20190801,
            .kem_preferences = &kyber_test_prefs,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .ecc_preferences = &s2n_ecc_preferences_20200310,
    };

    /* SIKE */
    const struct s2n_kem_group *sike_test_groups[] = {
#if EVP_APIS_SUPPORTED
            &s2n_x25519_sike_p434_r2,
#endif
            &s2n_secp256r1_sike_p434_r2,
    };

    const struct s2n_kem_preferences sike_test_prefs = {
            .kem_count = 0,
            .kems = NULL,
            .tls13_kem_group_count = s2n_array_len(sike_test_groups),
            .tls13_kem_groups = sike_test_groups,
    };

    const struct s2n_security_policy sike_test_policy = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &cipher_preferences_20190801,
            .kem_preferences = &sike_test_prefs,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .ecc_preferences = &s2n_ecc_preferences_20200310,
    };

    /* BIKE */
    const struct s2n_kem_group *bike_test_groups[] = {
#if EVP_APIS_SUPPORTED
            &s2n_x25519_bike1_l1_r2,
#endif
            &s2n_secp256r1_bike1_l1_r2,
    };

    const struct s2n_kem_preferences bike_test_prefs = {
            .kem_count = 0,
            .kems = NULL,
            .tls13_kem_group_count = s2n_array_len(bike_test_groups),
            .tls13_kem_groups = bike_test_groups,
    };

    const struct s2n_security_policy bike_test_policy = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &cipher_preferences_20190801,
            .kem_preferences = &bike_test_prefs,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .ecc_preferences = &s2n_ecc_preferences_20200310,
    };

    const struct s2n_kem_group *expected_kyber_group = &s2n_x25519_kyber_512_r2;
    const struct s2n_kem_group *expected_bike_group = &s2n_x25519_bike1_l1_r2;
    const struct s2n_kem_group *expected_sike_group = &s2n_x25519_sike_p434_r2;
    const struct s2n_ecc_named_curve *expected_curve = &s2n_ecc_curve_x25519;

    if (!s2n_is_evp_apis_supported()) {
        expected_kyber_group = &s2n_secp256r1_kyber_512_r2;
        expected_bike_group = &s2n_secp256r1_bike1_l1_r2;
        expected_sike_group = &s2n_secp256r1_sike_p434_r2;
        expected_curve = &s2n_ecc_curve_secp256r1;
    }

    struct pq_handshake_test_vector {
        const struct s2n_security_policy *client_policy;
        const struct s2n_security_policy *server_policy;
        const struct s2n_kem_group *expected_kem_group;
        const struct s2n_ecc_named_curve *expected_curve;
        bool should_send_ec_shares;
        bool hrr_expected;
    };

    /* Test vectors that expect to negotiate PQ assume that PQ is enabled in s2n.
     * If PQ is disabled, the expected negotiation outcome is overridden below
     * before performing the handshake test. */
    const struct pq_handshake_test_vector test_vectors[] = {
            /* Server supports all KEM groups; client sends a PQ key share and an EC key
             * share; server chooses to negotiate client's first choice PQ without HRR. */
            {
                    .client_policy = &security_policy_pq_tls_1_0_2020_12,
                    .server_policy = &security_policy_pq_tls_1_0_2020_12,
                    .expected_kem_group = expected_kyber_group,
                    .expected_curve = NULL,
                    .should_send_ec_shares = true,
                    .hrr_expected = false,
            },

            /* Server supports only one KEM group and it is the client's first choice;
             * client sends a PQ share and an EC share; server chooses to negotiate PQ
             * without HRR. */
            {
                    .client_policy = &security_policy_pq_tls_1_0_2020_12,
                    .server_policy = &kyber_test_policy,
                    .expected_kem_group = expected_kyber_group,
                    .expected_curve = NULL,
                    .should_send_ec_shares = true,
                    .hrr_expected = false,
            },

            /* Server supports only one KEM group and it is *not* the client's first choice;
             * client sends only a PQ key share for its first choice (no ECC shares sent);
             * server sends HRR and negotiates a mutually supported PQ group. */
            {
                    .client_policy = &security_policy_pq_tls_1_0_2020_12,
                    .server_policy = &bike_test_policy,
                    .expected_kem_group = expected_bike_group,
                    .expected_curve = NULL,
                    .should_send_ec_shares = false,
                    .hrr_expected = true,
            },
            {
                    .client_policy = &security_policy_pq_tls_1_0_2020_12,
                    .server_policy = &sike_test_policy,
                    .expected_kem_group = expected_sike_group,
                    .expected_curve = NULL,
                    .should_send_ec_shares = false,
                    .hrr_expected = true,
            },

            /* Server supports only one KEM group and it is *not* the client's first choice;
             * client sends a key share for its first PQ choice, and a share for its first EC
             * choice; server chooses to negotiate EC to avoid additional round trips. */
            {
                    .client_policy = &security_policy_pq_tls_1_0_2020_12,
                    .server_policy = &bike_test_policy,
                    .expected_kem_group = NULL,
                    .expected_curve = expected_curve,
                    .should_send_ec_shares = true,
                    .hrr_expected = false,
            },
            {
                    .client_policy = &security_policy_pq_tls_1_0_2020_12,
                    .server_policy = &sike_test_policy,
                    .expected_kem_group = NULL,
                    .expected_curve = expected_curve,
                    .should_send_ec_shares = true,
                    .hrr_expected = false,
            },

            /* Server does not support PQ; client sends a PQ key share and an EC key share;
             * server should negotiate EC without HRR. */
            {
                    .client_policy = &security_policy_pq_tls_1_0_2020_12,
                    .server_policy = &security_policy_test_all_tls13,
                    .expected_kem_group = NULL,
                    .expected_curve = expected_curve,
                    .should_send_ec_shares = true,
                    .hrr_expected = false,
            },

            /* Server does not support PQ; client sends a PQ key share, but no EC shares;
             * server should negotiate EC and send HRR. */
            {
                    .client_policy = &security_policy_pq_tls_1_0_2020_12,
                    .server_policy = &security_policy_test_all_tls13,
                    .expected_kem_group = NULL,
                    .expected_curve = expected_curve,
                    .should_send_ec_shares = false,
                    .hrr_expected = true,
            },

            /* Server supports PQ, but client does not. Client sent an EC share,
             * EC should be negotiated without HRR */
            {
                    .client_policy = &security_policy_test_all_tls13,
                    .server_policy = &security_policy_pq_tls_1_0_2020_12,
                    .expected_kem_group = NULL,
                    .expected_curve = expected_curve,
                    .should_send_ec_shares = true,
                    .hrr_expected = false,
            },

            /* Server supports PQ, but client does not. Client did not send any EC shares,
             * EC should be negotiated after exchanging HRR */
            {
                    .client_policy = &security_policy_test_all_tls13,
                    .server_policy = &security_policy_pq_tls_1_0_2020_12,
                    .expected_kem_group = NULL,
                    .expected_curve = expected_curve,
                    .should_send_ec_shares = false,
                    .hrr_expected = true,
            },
    };

    for (size_t i = 0; i < s2n_array_len(test_vectors); i++) {
        const struct pq_handshake_test_vector *vector = &test_vectors[i];
        const struct s2n_security_policy *client_policy = vector->client_policy;
        const struct s2n_security_policy *server_policy = vector->server_policy;
        const struct s2n_kem_group *kem_group = vector->expected_kem_group;
        const struct s2n_ecc_named_curve *curve = vector->expected_curve;
        bool should_send_ec_shares = vector->should_send_ec_shares;
        bool hrr_expected = vector->hrr_expected;

        if (!s2n_pq_is_enabled()) {
            /* If PQ is disabled, we always expected to negotiate ECC. */
            kem_group = NULL;
            curve = expected_curve;
        }

        EXPECT_SUCCESS(s2n_test_tls13_pq_handshake(client_policy, server_policy, kem_group, curve,
                should_send_ec_shares, hrr_expected));
    }

    END_TEST();
}
