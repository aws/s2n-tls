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
#include "tls/s2n_tls13_handshake.h"

#include <stdint.h>
#include <stdlib.h>

#include "api/s2n.h"
#include "crypto/s2n_fips.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_quic_support.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

/* Just to get access to the static functions / variables we need to test */
#include "tls/s2n_handshake_io.c"
#include "tls/s2n_handshake_transcript.c"
#include "tls/s2n_tls13_handshake.c"

#define S2N_SECRET_TYPE_COUNT 5
#define S2N_TEST_PSK_COUNT    10

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    /* Test wiping PSKs after use */
    {
        /* PSKs are wiped when chosen PSK is NULL */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.server_ecc_evp_params));
            conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

            const uint8_t psk_data[] = "test identity data";
            const uint8_t secret_data[] = "test secret data";
            for (size_t i = 0; i < S2N_TEST_PSK_COUNT; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &psk));
                EXPECT_OK(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));
                EXPECT_SUCCESS(s2n_psk_set_identity(psk, psk_data, sizeof(psk_data)));
                EXPECT_NOT_EQUAL(psk->identity.size, 0);
                EXPECT_NOT_EQUAL(psk->identity.data, NULL);
                EXPECT_SUCCESS(s2n_psk_set_secret(psk, secret_data, sizeof(secret_data)));
                EXPECT_NOT_EQUAL(psk->secret.size, 0);
                EXPECT_NOT_EQUAL(psk->secret.data, NULL);
            }

            EXPECT_NOT_EQUAL(conn->psk_params.psk_list.mem.allocated, 0);
            EXPECT_EQUAL(conn->psk_params.psk_list.len, S2N_TEST_PSK_COUNT);
            EXPECT_NULL(conn->psk_params.chosen_psk);

            DEFER_CLEANUP(struct s2n_blob shared_secret = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(conn, &shared_secret));

            /* Verify secrets are wiped */
            for (size_t i = 0; i < conn->psk_params.psk_list.len; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, i, (void **) &psk));
                EXPECT_NOT_EQUAL(psk->identity.size, 0);
                EXPECT_NULL(psk->secret.data);
                EXPECT_EQUAL(psk->secret.size, 0);
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* PSKs are wiped when chosen PSK is NOT NULL */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.server_ecc_evp_params));
            conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

            const uint8_t psk_data[] = "test identity data";
            const uint8_t secret_data[] = "test secret data";
            const uint8_t early_secret_data[SHA256_DIGEST_LENGTH] = "test early secret data";
            for (size_t i = 0; i < S2N_TEST_PSK_COUNT; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &psk));
                EXPECT_OK(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));
                EXPECT_SUCCESS(s2n_psk_set_identity(psk, psk_data, sizeof(psk_data)));
                EXPECT_NOT_EQUAL(psk->identity.size, 0);
                EXPECT_NOT_EQUAL(psk->identity.data, NULL);
                EXPECT_SUCCESS(s2n_psk_set_secret(psk, secret_data, sizeof(secret_data)));
                EXPECT_NOT_EQUAL(psk->secret.size, 0);
                EXPECT_NOT_EQUAL(psk->secret.data, NULL);
                EXPECT_SUCCESS(s2n_realloc(&psk->early_secret, sizeof(early_secret_data)));
                POSIX_CHECKED_MEMCPY(psk->early_secret.data, early_secret_data, sizeof(early_secret_data));
                EXPECT_NOT_EQUAL(psk->early_secret.size, 0);
                EXPECT_NOT_EQUAL(psk->early_secret.data, NULL);
            }

            /* Set chosen PSK */
            struct s2n_psk *chosen_psk = NULL;
            EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void **) &chosen_psk));
            EXPECT_NOT_NULL(chosen_psk);
            conn->psk_params.chosen_psk = chosen_psk;
            conn->psk_params.chosen_psk_wire_index = 0;

            EXPECT_NOT_EQUAL(conn->psk_params.psk_list.mem.allocated, 0);
            EXPECT_EQUAL(conn->psk_params.psk_list.len, S2N_TEST_PSK_COUNT);

            DEFER_CLEANUP(struct s2n_blob shared_secret = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(conn, &shared_secret));

            /* Verify secrets are wiped */
            for (size_t i = 0; i < conn->psk_params.psk_list.len; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, i, (void **) &psk));
                EXPECT_NOT_EQUAL(psk->identity.size, 0);
                EXPECT_NULL(psk->secret.data);
                EXPECT_EQUAL(psk->secret.size, 0);
                EXPECT_NULL(psk->early_secret.data);
                EXPECT_EQUAL(psk->early_secret.size, 0);
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test: Handshake self-talks using s2n_handshake_write_io and s2n_handshake_read_io */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;

        struct s2n_config *server_config, *client_config;
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

        uint8_t *cert_chain = NULL;
        uint8_t *private_key = NULL;
        uint32_t cert_chain_len = 0;
        uint32_t private_key_len = 0;

        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain, &cert_chain_len, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_ECDSA_P384_PKCS1_KEY, private_key, &private_key_len, S2N_MAX_TEST_PEM_SIZE));

        struct s2n_cert_chain_and_key *default_cert;
        EXPECT_NOT_NULL(default_cert = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem_bytes(default_cert, cert_chain, cert_chain_len, private_key, private_key_len));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, default_cert));

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        struct s2n_stuffer client_to_server = { 0 };
        struct s2n_stuffer server_to_client = { 0 };

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));

        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));

        struct s2n_blob server_seq = { .data = server_conn->secure->server_sequence_number, .size = sizeof(server_conn->secure->server_sequence_number) };
        S2N_BLOB_FROM_HEX(seq_0, "0000000000000000");
        S2N_BLOB_FROM_HEX(seq_1, "0000000000000001");

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

        /* Client sends ClientHello */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_HELLO);
        EXPECT_SUCCESS(s2n_handshake_write_io(client_conn));

        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_UNKNOWN_PROTOCOL_VERSION);

        s2n_tls13_connection_keys(server_secrets_0, server_conn);
        EXPECT_EQUAL(server_secrets_0.size, 0);

        EXPECT_EQUAL(server_conn->handshake.handshake_type, INITIAL);

        /* Server reads ClientHello */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
        EXPECT_SUCCESS(s2n_handshake_read_io(server_conn));

        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13); /* Server is now on TLS13 */
        EXPECT_EQUAL(server_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE | MIDDLEBOX_COMPAT);

        s2n_tls13_connection_keys(server_secrets, server_conn);
        EXPECT_EQUAL(server_secrets.size, SHA256_DIGEST_LENGTH);

        EXPECT_SUCCESS(s2n_conn_set_handshake_type(server_conn));

        /* Server sends ServerHello */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_HELLO);
        EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));

        /* Server sends CCS */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_CHANGE_CIPHER_SPEC);
        EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));
        S2N_BLOB_EXPECT_EQUAL(server_seq, seq_0);

        /* Server sends EncryptedExtensions */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), ENCRYPTED_EXTENSIONS);
        EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));
        S2N_BLOB_EXPECT_EQUAL(server_seq, seq_1);

        /* Server sends ServerCert */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_CERT);
        EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));

        /* Server sends CertVerify */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_CERT_VERIFY);
        EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));

        /* Client reads ServerHello */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
        EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

        /* Client reads CCS
         * The CCS message does not affect its place in the state machine. */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), ENCRYPTED_EXTENSIONS);
        EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

        s2n_tls13_connection_keys(client_secrets, client_conn);
        EXPECT_EQUAL(client_secrets.size, SHA256_DIGEST_LENGTH);

        /* Verify that derive and extract secrets match */
        S2N_BLOB_EXPECT_EQUAL(server_secrets.derive_secret, client_secrets.derive_secret);
        S2N_BLOB_EXPECT_EQUAL(server_secrets.extract_secret, client_secrets.extract_secret);

        /* Client reads Encrypted extensions */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), ENCRYPTED_EXTENSIONS);
        EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

        /* Client reads ServerCert */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_CERT);
        EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

        /* Client reads CertVerify */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_CERT_VERIFY);
        EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

        /* Server sends ServerFinished */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_FINISHED);
        EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));

        /* Client reads ServerFinished */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_FINISHED);
        EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

        /* Client sends CCS */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_CHANGE_CIPHER_SPEC);
        EXPECT_SUCCESS(s2n_handshake_write_io(client_conn));

        /* Client sends ClientFinished */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_FINISHED);
        EXPECT_SUCCESS(s2n_handshake_write_io(client_conn));

        /* Server reads CCS
         * The CCS message does not affect its place in the state machine. */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_FINISHED);
        EXPECT_SUCCESS(s2n_handshake_read_io(server_conn));

        /* Server reads ClientFinished */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_FINISHED);
        EXPECT_SUCCESS(s2n_handshake_read_io(server_conn));

        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

        /* Verify that derive and extract secrets match */
        S2N_BLOB_EXPECT_EQUAL(server_secrets.derive_secret, client_secrets.derive_secret);
        S2N_BLOB_EXPECT_EQUAL(server_secrets.extract_secret, client_secrets.extract_secret);

        /* Clean up */
        EXPECT_SUCCESS(s2n_stuffer_free(&client_to_server));
        EXPECT_SUCCESS(s2n_stuffer_free(&server_to_client));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(default_cert));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        free(private_key);
        free(cert_chain);
    };

    END_TEST();
    return 0;
}
