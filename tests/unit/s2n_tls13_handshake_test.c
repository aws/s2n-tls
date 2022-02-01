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

#include <stdint.h>
#include <stdlib.h>

#include "api/s2n.h"

#include "crypto/s2n_fips.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_quic_support.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/s2n_security_policies.h"
#include "utils/s2n_safety.h"

/* Just to get access to the static functions / variables we need to test */
#include "tls/s2n_handshake_io.c"
#include "tls/s2n_tls13_handshake.c"
#include "tls/s2n_handshake_transcript.c"

#define S2N_SECRET_TYPE_COUNT 5
#define S2N_TEST_PSK_COUNT 10

static int s2n_setup_tls13_secrets_prereqs(struct s2n_connection *conn)
{
    conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
    POSIX_GUARD_RESULT(s2n_tls13_calculate_digest(conn, conn->handshake.hashes->server_hello_digest));
    POSIX_GUARD_RESULT(s2n_tls13_calculate_digest(conn, conn->handshake.hashes->server_finished_digest));

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    POSIX_GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    POSIX_ENSURE_REF(ecc_pref);

    conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
    conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
    POSIX_GUARD(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.server_ecc_evp_params));
    POSIX_GUARD(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

    return S2N_SUCCESS;
}

static int s2n_test_tls13_handle_secrets(s2n_mode mode, uint8_t version, message_type_t *update_points, size_t update_points_len)
{
    for (size_t i = 0; i < S2N_MAX_HANDSHAKE_LENGTH; i++) {
        struct s2n_connection *conn;
        POSIX_ENSURE_REF(conn = s2n_connection_new(mode));
        POSIX_GUARD(s2n_setup_tls13_secrets_prereqs(conn));

        conn->actual_protocol_version = version;

        s2n_tls13_connection_keys(client_secrets, conn);

        DEFER_CLEANUP(struct s2n_blob empty_secret, s2n_free);
        POSIX_GUARD(s2n_alloc(&empty_secret, client_secrets.size));
        POSIX_GUARD(s2n_blob_zero(&empty_secret));
        POSIX_ENSURE_EQ(memcmp(empty_secret.data, client_secrets.extract_secret.data, client_secrets.extract_secret.size), 0);

        /* verify that that is the initial secret state */
        conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
        conn->handshake.message_number = i;

        POSIX_GUARD(s2n_tls13_handle_secrets(conn));

        bool expect_secret_updated = false;
        for (size_t j = 0; j < update_points_len; j++) {
            if (s2n_conn_get_current_message_type(conn) == update_points[j]) {
                expect_secret_updated = true;
                break;
            }
        }

        if (expect_secret_updated) {
            POSIX_ENSURE_NE(memcmp(empty_secret.data, client_secrets.extract_secret.data, empty_secret.size), 0);
        } else {
            POSIX_ENSURE_EQ(memcmp(empty_secret.data, client_secrets.extract_secret.data, empty_secret.size), 0);
        }

        POSIX_GUARD(s2n_connection_free(conn));
    }

    return S2N_SUCCESS;
}

static int s2n_test_secret_handler(void* context, struct s2n_connection *conn,
                                          s2n_secret_type_t secret_type,
                                          uint8_t *secret, uint8_t secret_size)
{
    uint8_t *secrets_handled = (uint8_t *) context;
    secrets_handled[secret_type] += 1;

    switch(secret_type) {
        case S2N_CLIENT_HANDSHAKE_TRAFFIC_SECRET:
            POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(conn), SERVER_HELLO);
            break;
        case S2N_SERVER_HANDSHAKE_TRAFFIC_SECRET:
            POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(conn), SERVER_HELLO);
            break;
        case S2N_SERVER_APPLICATION_TRAFFIC_SECRET:
            if (conn->mode == S2N_SERVER) {
                POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(conn), SERVER_FINISHED);
            } else {
                POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(conn), CLIENT_FINISHED);
            }
            /* Handshake secrets were already derived */
            POSIX_ENSURE_EQ(secrets_handled[S2N_CLIENT_HANDSHAKE_TRAFFIC_SECRET], 1);
            POSIX_ENSURE_EQ(secrets_handled[S2N_SERVER_HANDSHAKE_TRAFFIC_SECRET], 1);
            break;
        case S2N_CLIENT_APPLICATION_TRAFFIC_SECRET:
            POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(conn), CLIENT_FINISHED);
            /* Handshake secrets were already derived */
            POSIX_ENSURE_EQ(secrets_handled[S2N_CLIENT_HANDSHAKE_TRAFFIC_SECRET], 1);
            POSIX_ENSURE_EQ(secrets_handled[S2N_SERVER_HANDSHAKE_TRAFFIC_SECRET], 1);
            break;
        case S2N_CLIENT_EARLY_TRAFFIC_SECRET:
            POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
    }

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* Test: TLS 1.3 key and secrets generation is symmetrical */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        client_conn->actual_protocol_version = S2N_TLS13;
        server_conn->actual_protocol_version = S2N_TLS13;

        const struct s2n_ecc_preferences *server_ecc_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &server_ecc_preferences));
        EXPECT_NOT_NULL(server_ecc_preferences);

        struct s2n_stuffer client_hello_key_share;
        struct s2n_stuffer server_hello_key_share;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_hello_key_share, 1024));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_hello_key_share, 1024));

        /* Client sends ClientHello key_share */
        EXPECT_SUCCESS(s2n_extensions_client_key_share_send(client_conn, &client_hello_key_share));
        S2N_STUFFER_READ_EXPECT_EQUAL(&client_hello_key_share, TLS_EXTENSION_KEY_SHARE, uint16);
        S2N_STUFFER_READ_EXPECT_EQUAL(&client_hello_key_share, s2n_extensions_client_key_share_size(server_conn)
            - (S2N_SIZE_OF_EXTENSION_TYPE + S2N_SIZE_OF_EXTENSION_DATA_SIZE), uint16);

        /* Server configures the "supported_groups" shared with the client */
        server_conn->kex_params.mutually_supported_curves[0] = server_ecc_preferences->ecc_curves[0];

        EXPECT_SUCCESS(s2n_extensions_client_key_share_recv(server_conn, &client_hello_key_share));

        /* Server configures the "negotiated_curve" */
        server_conn->kex_params.server_ecc_evp_params.negotiated_curve = server_ecc_preferences->ecc_curves[0];

        /* Server sends ServerHello key_share */
        EXPECT_SUCCESS(s2n_extensions_server_key_share_send(server_conn, &server_hello_key_share));

        S2N_STUFFER_READ_EXPECT_EQUAL(&server_hello_key_share, TLS_EXTENSION_KEY_SHARE, uint16);
        S2N_STUFFER_READ_EXPECT_EQUAL(&server_hello_key_share, s2n_extensions_server_key_share_send_size(server_conn)
            - (S2N_SIZE_OF_EXTENSION_TYPE + S2N_SIZE_OF_EXTENSION_DATA_SIZE), uint16);
        EXPECT_SUCCESS(s2n_extensions_server_key_share_recv(client_conn, &server_hello_key_share));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_hello_key_share), 0);

        EXPECT_EQUAL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve, client_conn->kex_params.server_ecc_evp_params.negotiated_curve);

        client_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        server_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

        /* populating server hello hash is now a requirement for s2n_tls13_handle_handshake_traffic_secret */
        EXPECT_OK(s2n_tls13_calculate_digest(server_conn, server_conn->handshake.hashes->server_hello_digest));
        EXPECT_OK(s2n_tls13_calculate_digest(client_conn, client_conn->handshake.hashes->server_hello_digest));

        EXPECT_SUCCESS(s2n_tls13_handle_early_secret(server_conn));
        EXPECT_SUCCESS(s2n_tls13_handle_handshake_master_secret(server_conn));
        EXPECT_SUCCESS(s2n_tls13_handle_handshake_traffic_secret(server_conn, S2N_SERVER));
        EXPECT_EQUAL(server_conn->server, &server_conn->secure);
        EXPECT_SUCCESS(s2n_tls13_handle_handshake_traffic_secret(server_conn, S2N_CLIENT));
        EXPECT_EQUAL(server_conn->client, &server_conn->secure);

        EXPECT_SUCCESS(s2n_tls13_handle_early_secret(client_conn));
        EXPECT_SUCCESS(s2n_tls13_handle_handshake_master_secret(client_conn));
        EXPECT_SUCCESS(s2n_tls13_handle_handshake_traffic_secret(client_conn, S2N_SERVER));
        EXPECT_EQUAL(client_conn->server, &client_conn->secure);
        EXPECT_SUCCESS(s2n_tls13_handle_handshake_traffic_secret(client_conn, S2N_CLIENT));
        EXPECT_EQUAL(client_conn->client, &client_conn->secure);

        s2n_tls13_connection_keys(server_secrets, server_conn);
        s2n_tls13_connection_keys(client_secrets, client_conn);

        /* verify that derive and extract secrets match */
        S2N_BLOB_EXPECT_EQUAL(server_secrets.derive_secret, client_secrets.derive_secret);
        S2N_BLOB_EXPECT_EQUAL(server_secrets.extract_secret, client_secrets.extract_secret);

        /* verify that client and server finished secrets match */
        EXPECT_BYTEARRAY_EQUAL(server_conn->handshake.server_finished, client_conn->handshake.server_finished, server_secrets.size);
        EXPECT_BYTEARRAY_EQUAL(server_conn->handshake.client_finished, client_conn->handshake.client_finished, client_secrets.size);

        /* server writes message to client in plaintext */
        server_conn->server = &server_conn->initial;
        S2N_BLOB_FROM_HEX(deadbeef_from_server, "DEADBEEF");

        EXPECT_SUCCESS(s2n_record_write(server_conn, TLS_HANDSHAKE, &deadbeef_from_server));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->out), 9);
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->out));

        /* server writes message to client with encryption */
        server_conn->server = &server_conn->secure;
        EXPECT_SUCCESS(s2n_record_write(server_conn, TLS_APPLICATION_DATA, &deadbeef_from_server));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->out), 26);

        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->out, &client_conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->out, &client_conn->in, s2n_stuffer_data_available(&server_conn->out)));

        /* client reads encrypted message from server */
        client_conn->server = &client_conn->secure;
        EXPECT_SUCCESS(s2n_record_parse(client_conn));
        EXPECT_EQUAL(5, s2n_stuffer_data_available(&client_conn->in));
        S2N_STUFFER_READ_EXPECT_EQUAL(&client_conn->in, 0xDEADBEEF, uint32);
        S2N_STUFFER_READ_EXPECT_EQUAL(&client_conn->in, TLS_APPLICATION_DATA, uint8);

        /* client writes message to server in plaintext */
        client_conn->client = &client_conn->initial;
        S2N_BLOB_FROM_HEX(cafefood_from_client, "CAFED00D");
        EXPECT_SUCCESS(s2n_record_write(client_conn, TLS_HANDSHAKE, &cafefood_from_client));

        /* unencrypted length */
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->out), 9);
        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->out));

        /* let client write an encrypted message to server */
        client_conn->client = &client_conn->secure;
        EXPECT_SUCCESS(s2n_record_write(client_conn, TLS_APPLICATION_DATA, &cafefood_from_client));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->out), 26);
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->out, &server_conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->out, &server_conn->in, s2n_stuffer_data_available(&client_conn->out)));

        /* verify that server decrypts client's msg */
        server_conn->client = &server_conn->secure;
        EXPECT_SUCCESS(s2n_record_parse(server_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->in), 5);
        S2N_STUFFER_READ_EXPECT_EQUAL(&server_conn->in, 0xCAFED00D, uint32);
        S2N_STUFFER_READ_EXPECT_EQUAL(&server_conn->in, TLS_APPLICATION_DATA, uint8);

        /* populating server finished hash is now a requirement for s2n_tls13_handle_application_secrets */
        EXPECT_OK(s2n_tls13_calculate_digest(server_conn, server_conn->handshake.hashes->server_finished_digest));
        EXPECT_OK(s2n_tls13_calculate_digest(client_conn, client_conn->handshake.hashes->server_finished_digest));

        EXPECT_SUCCESS(s2n_tls13_handle_master_secret(client_conn));
        EXPECT_SUCCESS(s2n_tls13_handle_master_secret(server_conn));

        /* verify that application derive and extract secrets match */
        S2N_BLOB_EXPECT_EQUAL(server_secrets.derive_secret, client_secrets.derive_secret);
        S2N_BLOB_EXPECT_EQUAL(server_secrets.extract_secret, client_secrets.extract_secret);

        EXPECT_SUCCESS(s2n_tls13_handle_application_secret(server_conn, S2N_CLIENT));
        EXPECT_SUCCESS(s2n_tls13_handle_application_secret(server_conn, S2N_SERVER));
        EXPECT_SUCCESS(s2n_tls13_handle_application_secret(client_conn, S2N_CLIENT));
        EXPECT_SUCCESS(s2n_tls13_handle_application_secret(client_conn, S2N_SERVER));

        /* wipe all the stuffers */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->out));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->out));

        EXPECT_SUCCESS(s2n_record_write(server_conn, TLS_APPLICATION_DATA, &deadbeef_from_server));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->out), 26);

        /* test that client decrypts deadbeef correctly with application data */
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->out, &client_conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->out, &client_conn->in, s2n_stuffer_data_available(&server_conn->out)));
        EXPECT_SUCCESS(s2n_record_parse(client_conn));
        S2N_STUFFER_READ_EXPECT_EQUAL(&client_conn->in, 0xDEADBEEF, uint32);
        S2N_STUFFER_READ_EXPECT_EQUAL(&client_conn->in, TLS_APPLICATION_DATA, uint8);

        /* let client write an application message to server */
        EXPECT_SUCCESS(s2n_record_write(client_conn, TLS_APPLICATION_DATA, &cafefood_from_client));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->out), 26);
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->out, &server_conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->out, &server_conn->in, s2n_stuffer_data_available(&client_conn->out)));

        EXPECT_SUCCESS(s2n_record_parse(server_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->in), 5);
        S2N_STUFFER_READ_EXPECT_EQUAL(&server_conn->in, 0xCAFED00D, uint32);
        S2N_STUFFER_READ_EXPECT_EQUAL(&server_conn->in, TLS_APPLICATION_DATA, uint8);

        /* Clean up */
        EXPECT_SUCCESS(s2n_stuffer_free(&client_hello_key_share));
        EXPECT_SUCCESS(s2n_stuffer_free(&server_hello_key_share));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
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

            conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.server_ecc_evp_params));
            conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

            const uint8_t psk_data[] = "test identity data";
            const uint8_t secret_data[] = "test secret data";
            for (size_t i = 0; i < S2N_TEST_PSK_COUNT; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
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

            EXPECT_SUCCESS(s2n_tls13_handle_handshake_master_secret(conn));

            /* Verify secrets are wiped */
            for (size_t i = 0; i < conn->psk_params.psk_list.len; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, i, (void**)&psk));
                EXPECT_NOT_EQUAL(psk->identity.size, 0);
                EXPECT_NULL(psk->secret.data);
                EXPECT_EQUAL(psk->secret.size, 0);
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* PSKs are wiped when chosen PSK is NOT NULL */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.server_ecc_evp_params));
            conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_preferences->ecc_curves[0];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

            const uint8_t psk_data[] = "test identity data";
            const uint8_t secret_data[] = "test secret data";
            const uint8_t early_secret_data[SHA256_DIGEST_LENGTH] = "test early secret data";
            for (size_t i = 0; i < S2N_TEST_PSK_COUNT; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
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
            EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, 0, (void**) &chosen_psk));
            EXPECT_NOT_NULL(chosen_psk);
            conn->psk_params.chosen_psk = chosen_psk;
            conn->psk_params.chosen_psk_wire_index = 0;

            EXPECT_NOT_EQUAL(conn->psk_params.psk_list.mem.allocated, 0);
            EXPECT_EQUAL(conn->psk_params.psk_list.len, S2N_TEST_PSK_COUNT);

            EXPECT_SUCCESS(s2n_tls13_handle_handshake_master_secret(conn));

            /* Verify secrets are wiped */
            for (size_t i = 0; i < conn->psk_params.psk_list.len; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, i, (void**)&psk));
                EXPECT_NOT_EQUAL(psk->identity.size, 0);
                EXPECT_NULL(psk->secret.data);
                EXPECT_EQUAL(psk->secret.size, 0);
                EXPECT_NULL(psk->early_secret.data);
                EXPECT_EQUAL(psk->early_secret.size, 0);
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    /* Test: s2n_tls13_handle_secrets */
    {
        /* Test: TLS1.2 is always a no-op */
        {
            EXPECT_SUCCESS(s2n_test_tls13_handle_secrets(S2N_CLIENT, S2N_TLS12, NULL, 0));
            EXPECT_SUCCESS(s2n_test_tls13_handle_secrets(S2N_SERVER, S2N_TLS12, NULL, 0));
        }

        /* Test: TLS1.3 client triggers a key update on correct messages */
        {
            message_type_t client_secret_update_points[] = { SERVER_HELLO, CLIENT_FINISHED };
            EXPECT_SUCCESS(s2n_test_tls13_handle_secrets(S2N_CLIENT, S2N_TLS13,
                    client_secret_update_points, s2n_array_len(client_secret_update_points)));
        }

        /* Test: TLS1.3 server triggers a key update on correct messages */
        {
            message_type_t server_secret_update_points[] = { CLIENT_HELLO, SERVER_HELLO, SERVER_FINISHED };
            EXPECT_SUCCESS(s2n_test_tls13_handle_secrets(S2N_SERVER, S2N_TLS13,
                    server_secret_update_points, s2n_array_len(server_secret_update_points)));
        }

        /* Test: secret handlers called when QUIC enabled */
        {
            /* Test: secret handlers NOT called when QUIC NOT enabled */
            {
                const uint8_t expected_secrets_handled[S2N_SECRET_TYPE_COUNT] = { 0 };
                for (uint8_t version = S2N_TLS12; version <= S2N_TLS13; version++) {
                    for (s2n_mode mode = 0; mode <= 1; mode++) {
                        uint8_t secrets_handled[S2N_SECRET_TYPE_COUNT] = { 0 };

                        for (size_t i = 0; i < S2N_MAX_HANDSHAKE_LENGTH; i++) {
                            struct s2n_connection *conn;
                            EXPECT_NOT_NULL(conn = s2n_connection_new(mode));
                            EXPECT_SUCCESS(s2n_setup_tls13_secrets_prereqs(conn));

                            conn->actual_protocol_version = version;
                            conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
                            conn->handshake.message_number = i;

                            EXPECT_SUCCESS(s2n_connection_set_secret_callback(conn, s2n_test_secret_handler, secrets_handled));
                            EXPECT_SUCCESS(s2n_tls13_handle_secrets(conn));

                            EXPECT_SUCCESS(s2n_connection_free(conn));
                        }

                        EXPECT_BYTEARRAY_EQUAL(secrets_handled, expected_secrets_handled, sizeof(expected_secrets_handled));
                    }
                }
            }

            /* Test: secret handlers called when QUIC enabled */
            {
                struct s2n_config *config;
                EXPECT_NOT_NULL(config = s2n_config_new());
                EXPECT_SUCCESS(s2n_config_enable_quic(config));

                const uint8_t expected_secrets_handled[S2N_SECRET_TYPE_COUNT] = {
                    [S2N_CLIENT_HANDSHAKE_TRAFFIC_SECRET] = 1,
                    [S2N_SERVER_HANDSHAKE_TRAFFIC_SECRET] = 1,
                    [S2N_CLIENT_APPLICATION_TRAFFIC_SECRET] = 1,
                    [S2N_SERVER_APPLICATION_TRAFFIC_SECRET] = 1,
                };

                for (s2n_mode mode = 0; mode <= 1; mode++) {
                    uint8_t secrets_handled[S2N_SECRET_TYPE_COUNT] = { 0 };

                    for (size_t i = 0; i < S2N_MAX_HANDSHAKE_LENGTH; i++) {
                        struct s2n_connection *conn;
                        EXPECT_NOT_NULL(conn = s2n_connection_new(mode));
                        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
                        EXPECT_SUCCESS(s2n_setup_tls13_secrets_prereqs(conn));

                        conn->early_data_state = S2N_EARLY_DATA_NOT_REQUESTED;
                        conn->actual_protocol_version = S2N_TLS13;
                        conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
                        conn->handshake.message_number = i;

                        EXPECT_SUCCESS(s2n_connection_set_secret_callback(conn, s2n_test_secret_handler, secrets_handled));
                        EXPECT_SUCCESS(s2n_tls13_handle_secrets(conn));

                        EXPECT_SUCCESS(s2n_connection_free(conn));
                    }

                    EXPECT_BYTEARRAY_EQUAL(secrets_handled, expected_secrets_handled, sizeof(expected_secrets_handled));
                }

                EXPECT_SUCCESS(s2n_config_free(config));
            }
        }
    }

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

        struct s2n_stuffer client_to_server;
        struct s2n_stuffer server_to_client;

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_to_server, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_to_client, 0));

        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_to_client, &client_to_server, client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&client_to_server, &server_to_client, server_conn));

        struct s2n_blob server_seq = { .data = server_conn->secure.server_sequence_number,.size = sizeof(server_conn->secure.server_sequence_number) };
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
    }

    END_TEST();
    return 0;
}
