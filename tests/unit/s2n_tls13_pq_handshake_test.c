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
#include "crypto/s2n_fips.h"
#include "s2n.h"
#include "tls/s2n_handshake.h"

/* Include C file directly to access static functions */
#include "tls/s2n_handshake_io.c"

static int do_handshake(const struct s2n_security_policy *client_sec_policy,
        const struct s2n_security_policy *server_sec_policy, const struct s2n_kem_group *expected_kem_group,
        const struct s2n_ecc_named_curve *expected_curve, bool should_send_ec_shares, bool hrr_expected) {
    /* XOR check: can expect to negotiate either a KEM group, or a classic EC curve, but not both/neither */
    ENSURE_POSIX((expected_kem_group == NULL) != (expected_curve == NULL), S2N_ERR_SAFETY);

    /* Set up connections */
    struct s2n_connection *client_conn = NULL, *server_conn = NULL;
    notnull_check(client_conn = s2n_connection_new(S2N_CLIENT));
    notnull_check(server_conn = s2n_connection_new(S2N_SERVER));

    struct s2n_config *client_config = NULL, *server_config = NULL;
    notnull_check(client_config = s2n_config_new());
    notnull_check(server_config = s2n_config_new());

    char cert_chain[S2N_MAX_TEST_PEM_SIZE] = { 0 }, private_key[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    struct s2n_cert_chain_and_key *chain_and_key = NULL;
    notnull_check(chain_and_key = s2n_cert_chain_and_key_new());
    GUARD(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
    GUARD(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));
    GUARD(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain, private_key));
    GUARD(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));
    GUARD(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

    GUARD(s2n_connection_set_config(client_conn, client_config));
    GUARD(s2n_connection_set_config(server_conn, server_config));

    struct s2n_stuffer client_to_server = { 0 }, server_to_client = { 0 };
    GUARD(s2n_stuffer_growable_alloc(&client_to_server, 2048));
    GUARD(s2n_stuffer_growable_alloc(&server_to_client, 2048));

    GUARD(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));
    GUARD(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));

    client_conn->security_policy_override = client_sec_policy;
    server_conn->security_policy_override = server_sec_policy;

    /* Client sends ClientHello */
    if (!should_send_ec_shares) {
        /* In certain tests, we do not want to send any classic EC shares in order to force
         * the server to choose PQ with HRR for negotiation. */
        GUARD(s2n_connection_set_keyshare_by_name_for_testing(client_conn, "none"));
    }
    eq_check(s2n_conn_get_current_message_type(client_conn), CLIENT_HELLO);
    GUARD(s2n_handshake_write_io(client_conn));

    eq_check(client_conn->actual_protocol_version, S2N_TLS13);
    eq_check(server_conn->actual_protocol_version, 0); /* Won't get set until after server reads ClientHello */
    eq_check(client_conn->handshake.handshake_type,  INITIAL);

    /* Server reads ClientHello */
    eq_check(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
    GUARD(s2n_handshake_read_io(server_conn));

    eq_check(server_conn->actual_protocol_version, S2N_TLS13); /* Server is now on TLS13 */

    /* Assert that the server chose the correct group */
    if (expected_kem_group) {
        eq_check(expected_kem_group, server_conn->secure.server_kem_group_params.kem_group);
        eq_check(expected_kem_group->kem, server_conn->secure.server_kem_group_params.kem_params.kem);
        eq_check(expected_kem_group->curve, server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        eq_check(NULL, server_conn->secure.server_ecc_evp_params.negotiated_curve);
    } else {
        eq_check(NULL, server_conn->secure.server_kem_group_params.kem_group);
        eq_check(NULL, server_conn->secure.server_kem_group_params.kem_params.kem);
        eq_check(NULL, server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        eq_check(expected_curve, server_conn->secure.server_ecc_evp_params.negotiated_curve);
    }

    /* Server sends ServerHello or HRR */
    GUARD(s2n_conn_set_handshake_type(server_conn));
    if (hrr_expected) {
        eq_check(s2n_conn_get_current_message_type(server_conn), HELLO_RETRY_MSG);
    } else {
        eq_check(s2n_conn_get_current_message_type(server_conn), SERVER_HELLO);
    }
    GUARD(s2n_handshake_write_io(server_conn));

    /* Server sends CCS */
    eq_check(s2n_conn_get_current_message_type(server_conn), SERVER_CHANGE_CIPHER_SPEC);
    GUARD(s2n_handshake_write_io(server_conn));

    if (hrr_expected) {
        /* Client reads HRR */
        eq_check(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
        GUARD(s2n_handshake_read_io(client_conn));
        GUARD(s2n_conn_set_handshake_type(client_conn));
        ne_check(0, client_conn->handshake.handshake_type & HELLO_RETRY_REQUEST);

        /* Client reads CCS */
        eq_check(s2n_conn_get_current_message_type(client_conn), CLIENT_CHANGE_CIPHER_SPEC);
        GUARD(s2n_handshake_read_io(client_conn));

        /* Client sends CCS and new ClientHello */
        eq_check(s2n_conn_get_current_message_type(client_conn), CLIENT_CHANGE_CIPHER_SPEC);
        GUARD(s2n_handshake_write_io(client_conn));
        eq_check(s2n_conn_get_current_message_type(client_conn), CLIENT_HELLO);
        GUARD(s2n_handshake_write_io(client_conn));

        /* Server reads CCS (doesn't change state machine) */
        eq_check(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
        GUARD(s2n_handshake_read_io(server_conn));

        /* Server reads new ClientHello */
        eq_check(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
        GUARD(s2n_handshake_read_io(server_conn));

        /* Server sends ServerHello */
        eq_check(s2n_conn_get_current_message_type(server_conn), SERVER_HELLO);
        GUARD(s2n_handshake_write_io(server_conn));
    }

    /* Client reads ServerHello */
    eq_check(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
    GUARD(s2n_handshake_read_io(client_conn));

    /* We've gotten far enough in the handshake that both client and server should have
     * derived the shared secrets, so we don't send/receive any more messages. */

    /* Assert that the correct group was negotiated (we re-check the server group to assert that
     * nothing unexpected changed between then and now while e.g. processing HRR) */
    if (expected_kem_group) {
        eq_check(expected_kem_group, client_conn->secure.server_kem_group_params.kem_group);
        eq_check(expected_kem_group->kem, client_conn->secure.server_kem_group_params.kem_params.kem);
        eq_check(expected_kem_group->curve, client_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        eq_check(NULL, client_conn->secure.server_ecc_evp_params.negotiated_curve);

        eq_check(expected_kem_group, server_conn->secure.server_kem_group_params.kem_group);
        eq_check(expected_kem_group->kem, server_conn->secure.server_kem_group_params.kem_params.kem);
        eq_check(expected_kem_group->curve, server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        eq_check(NULL, server_conn->secure.server_ecc_evp_params.negotiated_curve);
    } else {
        eq_check(NULL, client_conn->secure.server_kem_group_params.kem_group);
        eq_check(NULL, client_conn->secure.server_kem_group_params.kem_params.kem);
        eq_check(NULL, client_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        eq_check(expected_curve, client_conn->secure.server_ecc_evp_params.negotiated_curve);

        eq_check(NULL, server_conn->secure.server_kem_group_params.kem_group);
        eq_check(NULL, server_conn->secure.server_kem_group_params.kem_params.kem);
        eq_check(NULL, server_conn->secure.server_kem_group_params.ecc_params.negotiated_curve);
        eq_check(expected_curve, server_conn->secure.server_ecc_evp_params.negotiated_curve);
    }

    /* Verify basic properties of secrets */
    s2n_tls13_connection_keys(server_secrets, server_conn);
    s2n_tls13_connection_keys(client_secrets, client_conn);
    notnull_check(server_secrets.extract_secret.data);
    notnull_check(server_secrets.derive_secret.data);
    notnull_check(client_secrets.extract_secret.data);
    notnull_check(client_secrets.derive_secret.data);
    eq_check(server_conn->secure.cipher_suite, client_conn->secure.cipher_suite);
    if (server_conn->secure.cipher_suite == &s2n_tls13_aes_256_gcm_sha384) {
        eq_check(server_secrets.size, 48);
        eq_check(client_secrets.size, 48);
    } else {
        eq_check(server_secrets.size, 32);
        eq_check(client_secrets.size, 32);
    }

    /* Verify secrets aren't just zero'ed memory */
    uint8_t all_zeros[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
    memset_check((void *)all_zeros, 0, S2N_TLS13_SECRET_MAX_LEN);
    ne_check(0, memcmp(all_zeros, client_secrets.derive_secret.data, client_secrets.derive_secret.size));
    ne_check(0, memcmp(all_zeros, client_secrets.extract_secret.data, client_secrets.extract_secret.size));
    ne_check(0, memcmp(all_zeros, server_secrets.derive_secret.data, server_secrets.derive_secret.size));
    ne_check(0, memcmp(all_zeros, server_secrets.extract_secret.data, server_secrets.extract_secret.size));

    /* Verify client and server secrets are equal to each other */
    eq_check(server_secrets.derive_secret.size, client_secrets.derive_secret.size);
    eq_check(0, memcmp(server_secrets.derive_secret.data, client_secrets.derive_secret.data, client_secrets.derive_secret.size));
    eq_check(server_secrets.extract_secret.size, client_secrets.extract_secret.size);
    eq_check(0, memcmp(server_secrets.extract_secret.data, client_secrets.extract_secret.data, client_secrets.extract_secret.size));

    /* Clean up */
    GUARD(s2n_stuffer_free(&client_to_server));
    GUARD(s2n_stuffer_free(&server_to_client));

    GUARD(s2n_connection_free(client_conn));
    GUARD(s2n_connection_free(server_conn));

    GUARD(s2n_cert_chain_and_key_free(chain_and_key));
    GUARD(s2n_config_free(server_config));
    GUARD(s2n_config_free(client_config));

    return S2N_SUCCESS;
}

int main() {
    BEGIN_TEST();

    if (s2n_is_in_fips_mode()) {
        END_TEST();
    }

#if !defined(S2N_NO_PQ)

    EXPECT_SUCCESS(s2n_enable_tls13());

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

    /* Server supports all KEM groups; client sends a PQ key share and an EC key share; server chooses
     * to negotiate client's first choice PQ without HRR. */
    EXPECT_SUCCESS(do_handshake(&security_policy_kyberbikesike_test_tls_1_0_2020_09,
            &security_policy_kyberbikesike_test_tls_1_0_2020_09, expected_kyber_group, NULL, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_kyber_test_tls_1_0_2020_09,
            &security_policy_kyberbikesike_test_tls_1_0_2020_09, expected_kyber_group, NULL, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_bike_test_tls_1_0_2020_09,
            &security_policy_kyberbikesike_test_tls_1_0_2020_09, expected_bike_group, NULL, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_sike_test_tls_1_0_2020_09,
            &security_policy_kyberbikesike_test_tls_1_0_2020_09, expected_sike_group, NULL, true, false));

    /* Server supports only one KEM group and it is the client's first choice; client sends a PQ share
     * and an EC share; server chooses to negotiate PQ without HRR. */
    EXPECT_SUCCESS(do_handshake(&security_policy_kyberbikesike_test_tls_1_0_2020_09,
            &security_policy_kyber_test_tls_1_0_2020_09, expected_kyber_group, NULL, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_kyber_test_tls_1_0_2020_09,
            &security_policy_kyber_test_tls_1_0_2020_09, expected_kyber_group, NULL, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_sike_test_tls_1_0_2020_09,
            &security_policy_sike_test_tls_1_0_2020_09, expected_sike_group, NULL, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_bike_test_tls_1_0_2020_09,
            &security_policy_bike_test_tls_1_0_2020_09, expected_bike_group, NULL, true, false));

    /* Server supports only one KEM group and it is *not* the client's first choice; client sends
     * only a PQ key share for its first choice (no ECC shares sent); server sends HRR and
     * negotiates a mutually supported PQ group. */
    EXPECT_SUCCESS(do_handshake(&security_policy_kyberbikesike_test_tls_1_0_2020_09,
            &security_policy_bike_test_tls_1_0_2020_09, expected_bike_group, NULL, false, true));
    EXPECT_SUCCESS(do_handshake(&security_policy_kyberbikesike_test_tls_1_0_2020_09,
            &security_policy_sike_test_tls_1_0_2020_09, expected_sike_group, NULL, false, true));

    /* Server supports only one KEM group and it is *not* the client's first choice; client sends
     * a key share for its first PQ choice, and a share for its first EC choice; server chooses
     * to negotiate EC to avoid additional round trips. */
    EXPECT_SUCCESS(do_handshake(&security_policy_kyberbikesike_test_tls_1_0_2020_09,
            &security_policy_bike_test_tls_1_0_2020_09, NULL, expected_curve, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_kyberbikesike_test_tls_1_0_2020_09,
            &security_policy_sike_test_tls_1_0_2020_09, NULL, expected_curve, true, false));

    /* Client and server both support PQ, but have no mutually supported PQ groups; client
     * sent PQ and EC shares; EC should be negotiated without HRR. */
    EXPECT_SUCCESS(do_handshake(&security_policy_kyber_test_tls_1_0_2020_09,
            &security_policy_bike_test_tls_1_0_2020_09, NULL, expected_curve, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_kyber_test_tls_1_0_2020_09,
            &security_policy_sike_test_tls_1_0_2020_09, NULL, expected_curve, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_sike_test_tls_1_0_2020_09,
            &security_policy_kyber_test_tls_1_0_2020_09, NULL, expected_curve, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_sike_test_tls_1_0_2020_09,
            &security_policy_bike_test_tls_1_0_2020_09, NULL, expected_curve, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_bike_test_tls_1_0_2020_09,
            &security_policy_kyber_test_tls_1_0_2020_09, NULL, expected_curve, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_bike_test_tls_1_0_2020_09,
            &security_policy_sike_test_tls_1_0_2020_09, NULL, expected_curve, true, false));

    /* Client and server both support PQ, but have no mutually supported PQ groups; client
     * sent only a PQ share (no EC); server should choose to negotiate EC and send HRR. */
    EXPECT_SUCCESS(do_handshake(&security_policy_kyber_test_tls_1_0_2020_09,
            &security_policy_bike_test_tls_1_0_2020_09, NULL, expected_curve, false, true));
    EXPECT_SUCCESS(do_handshake(&security_policy_kyber_test_tls_1_0_2020_09,
            &security_policy_sike_test_tls_1_0_2020_09, NULL, expected_curve, false, true));
    EXPECT_SUCCESS(do_handshake(&security_policy_sike_test_tls_1_0_2020_09,
            &security_policy_kyber_test_tls_1_0_2020_09, NULL, expected_curve, false, true));
    EXPECT_SUCCESS(do_handshake(&security_policy_sike_test_tls_1_0_2020_09,
            &security_policy_bike_test_tls_1_0_2020_09, NULL, expected_curve, false, true));
    EXPECT_SUCCESS(do_handshake(&security_policy_bike_test_tls_1_0_2020_09,
            &security_policy_kyber_test_tls_1_0_2020_09, NULL, expected_curve, false, true));
    EXPECT_SUCCESS(do_handshake(&security_policy_bike_test_tls_1_0_2020_09,
            &security_policy_sike_test_tls_1_0_2020_09, NULL, expected_curve, false, true));

    /* Server does not support PQ at all; client sends a PQ key share and an EC key share;
     * server should negotiate EC without HRR. */
    EXPECT_SUCCESS(do_handshake(&security_policy_kyberbikesike_test_tls_1_0_2020_09,
            &security_policy_test_all_tls13, NULL, expected_curve, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_bike_test_tls_1_0_2020_09,
            &security_policy_test_all_tls13, NULL, expected_curve, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_sike_test_tls_1_0_2020_09,
            &security_policy_test_all_tls13, NULL, expected_curve, true, false));
    EXPECT_SUCCESS(do_handshake(&security_policy_kyber_test_tls_1_0_2020_09,
            &security_policy_test_all_tls13, NULL, expected_curve, true, false));

    /* Server does not support PQ at all; client sends a PQ key share, but no EC shares;
     * server should negotiate EC and send HRR. */
    EXPECT_SUCCESS(do_handshake(&security_policy_kyberbikesike_test_tls_1_0_2020_09,
            &security_policy_test_all_tls13, NULL, expected_curve, false, true));
    EXPECT_SUCCESS(do_handshake(&security_policy_bike_test_tls_1_0_2020_09,
            &security_policy_test_all_tls13, NULL, expected_curve, false, true));
    EXPECT_SUCCESS(do_handshake(&security_policy_sike_test_tls_1_0_2020_09,
            &security_policy_test_all_tls13, NULL, expected_curve, false, true));
    EXPECT_SUCCESS(do_handshake(&security_policy_kyber_test_tls_1_0_2020_09,
            &security_policy_test_all_tls13, NULL, expected_curve, false, true));

    /* Server supports PQ, but client does not. Client sent an EC share, EC should be negotiated
     * without HRR */
    EXPECT_SUCCESS(do_handshake(&security_policy_test_all_tls13,
            &security_policy_kyberbikesike_test_tls_1_0_2020_09, NULL, expected_curve, true, false));

    /* Server supports PQ, but client does not. Client did not send any EC shares, EC should
     * be negotiated after exchanging HRR */
    EXPECT_SUCCESS(do_handshake(&security_policy_test_all_tls13,
            &security_policy_kyberbikesike_test_tls_1_0_2020_09, NULL, expected_curve, false, true));

#endif

    END_TEST();
}
