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

#include <s2n.h>

#include "crypto/s2n_fips.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/s2n_ecc_preferences.h"
#include "utils/s2n_safety.h"

/* Just to get access to the static functions / variables we need to test */
#include "tls/s2n_handshake_io.c"
#include "tls/s2n_tls13_handshake.c"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: TLS 1.3 key and secrets generation is symmetrical */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        client_conn->actual_protocol_version = S2N_TLS13;
        server_conn->actual_protocol_version = S2N_TLS13;
        
        const struct s2n_ecc_preferences *server_ecc_preferences = server_conn->config->ecc_preferences;

        struct s2n_stuffer client_hello_key_share;
        struct s2n_stuffer server_hello_key_share;
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_hello_key_share, 1024));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_hello_key_share, 1024));

        /* Client sends ClientHello key_share */
        EXPECT_SUCCESS(s2n_extensions_client_key_share_send(client_conn, &client_hello_key_share));
        S2N_STUFFER_READ_EXPECT_EQUAL(&client_hello_key_share, TLS_EXTENSION_KEY_SHARE, uint16);
        S2N_STUFFER_READ_EXPECT_EQUAL(&client_hello_key_share, s2n_extensions_client_key_share_size(server_conn)
            - (S2N_SIZE_OF_EXTENSION_TYPE + S2N_SIZE_OF_EXTENSION_DATA_SIZE), uint16);

        EXPECT_SUCCESS(s2n_extensions_client_key_share_recv(server_conn, &client_hello_key_share));

        /* Server configures the "negotiated_curve" */
        server_conn->secure.server_ecc_evp_params.negotiated_curve = server_ecc_preferences->ecc_curves[0];

        /* Server sends ServerHello key_share */
        EXPECT_SUCCESS(s2n_extensions_server_key_share_send(server_conn, &server_hello_key_share));

        S2N_STUFFER_READ_EXPECT_EQUAL(&server_hello_key_share, TLS_EXTENSION_KEY_SHARE, uint16);
        S2N_STUFFER_READ_EXPECT_EQUAL(&server_hello_key_share, s2n_extensions_server_key_share_send_size(server_conn)
            - (S2N_SIZE_OF_EXTENSION_TYPE + S2N_SIZE_OF_EXTENSION_DATA_SIZE), uint16);
        EXPECT_SUCCESS(s2n_extensions_server_key_share_recv(client_conn, &server_hello_key_share));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_hello_key_share), 0);

        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, client_conn->secure.server_ecc_evp_params.negotiated_curve);

        DEFER_CLEANUP(struct s2n_blob server_shared_secret = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob client_shared_secret = { 0 }, s2n_free);

        client_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        server_conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

        /* test that ecdhe shared secret generation matches */
        EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(server_conn, &server_shared_secret));
        EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(client_conn, &client_shared_secret));

        S2N_BLOB_EXPECT_EQUAL(server_shared_secret, client_shared_secret);

        /* test handle handshake secrets */
        EXPECT_SUCCESS(s2n_tls13_handle_handshake_secrets(server_conn));
        EXPECT_SUCCESS(s2n_tls13_handle_handshake_secrets(client_conn));

        s2n_tls13_connection_keys(server_secrets, server_conn);
        s2n_tls13_connection_keys(client_secrets, client_conn);

        /* verify that derive and extract secrets match */
        S2N_BLOB_EXPECT_EQUAL(server_secrets.derive_secret, client_secrets.derive_secret);
        S2N_BLOB_EXPECT_EQUAL(server_secrets.extract_secret, client_secrets.extract_secret);

        /* verify that client and server finished secrets match */
        EXPECT_BYTEARRAY_EQUAL(server_conn->handshake.server_finished, client_conn->handshake.server_finished, server_secrets.size);
        EXPECT_BYTEARRAY_EQUAL(server_conn->handshake.client_finished, client_conn->handshake.client_finished, client_secrets.size);

        /* server writes message to client in plaintext */
        S2N_BLOB_FROM_HEX(deadbeef_from_server, "DEADBEEF");

        EXPECT_SUCCESS(s2n_record_write(server_conn, TLS_APPLICATION_DATA, &deadbeef_from_server));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->out), 9);
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->out));

        /* server writes message to client with encryption */
        server_conn->server = &server_conn->secure;
        EXPECT_SUCCESS(s2n_record_write(server_conn, TLS_APPLICATION_DATA, &deadbeef_from_server));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->out), 26);

        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->out, &client_conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->out, &client_conn->in, s2n_stuffer_data_available(&server_conn->out)));

        client_conn->server = &client_conn->secure;
        EXPECT_SUCCESS(s2n_record_parse(client_conn));
        EXPECT_EQUAL(5, s2n_stuffer_data_available(&client_conn->in));
        S2N_STUFFER_READ_EXPECT_EQUAL(&client_conn->in, 0xDEADBEEF, uint32);
        S2N_STUFFER_READ_EXPECT_EQUAL(&client_conn->in, TLS_APPLICATION_DATA, uint8);

        S2N_BLOB_FROM_HEX(cafefood_from_client, "CAFED00D");

        EXPECT_SUCCESS(s2n_record_write(client_conn, TLS_APPLICATION_DATA, &cafefood_from_client));

        /* unencrypted length */
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->out), 9);
        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->out));
        client_conn->client = &client_conn->secure;

        /* let client write a message to server */
        EXPECT_SUCCESS(s2n_record_write(client_conn, TLS_APPLICATION_DATA, &cafefood_from_client));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->out), 26);
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->out, &server_conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->out, &server_conn->in, s2n_stuffer_data_available(&client_conn->out)));

        /* if aead payload is parsed as plaintext, it would be of length 21 */
        EXPECT_SUCCESS(s2n_record_parse(server_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->in), 21);
        EXPECT_SUCCESS(s2n_stuffer_reread(&client_conn->out));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->out, &server_conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->out, &server_conn->in, s2n_stuffer_data_available(&client_conn->out)));

        /* verify that server decrypts client's msg */
        server_conn->client = &server_conn->secure;
        EXPECT_SUCCESS(s2n_record_parse(server_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&server_conn->in), 5);
        S2N_STUFFER_READ_EXPECT_EQUAL(&server_conn->in, 0xCAFED00D, uint32);
        S2N_STUFFER_READ_EXPECT_EQUAL(&server_conn->in, TLS_APPLICATION_DATA, uint8);

        EXPECT_SUCCESS(s2n_tls13_handle_application_secrets(server_conn));
        EXPECT_SUCCESS(s2n_tls13_handle_application_secrets(client_conn));

        /* verify that application derive and extract secrets match */
        S2N_BLOB_EXPECT_EQUAL(server_secrets.derive_secret, client_secrets.derive_secret);
        S2N_BLOB_EXPECT_EQUAL(server_secrets.extract_secret, client_secrets.extract_secret);

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

    /* Test: s2n_conn_pre_handshake_hashes_update handlers */
    {
        S2N_BLOB_FROM_HEX(empty_secret, "0000000000000000000000000000000000000000000000000000000000000000");

        s2n_mode modes[] = { S2N_CLIENT, S2N_SERVER };

        /* we ensure this works in both client and server modes */
        for (int m = 0; m < s2n_array_len(modes); m++) {
            for (int i = 0; i < S2N_MAX_HANDSHAKE_LENGTH; i++) {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(modes[m]));

                conn->actual_protocol_version = S2N_TLS13;
                conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

                s2n_tls13_connection_keys(client_secrets, conn);
                S2N_BLOB_EXPECT_EQUAL(empty_secret, client_secrets.extract_secret);

                conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
                conn->handshake.message_number = i;

                /* trigger s2n_conn_pre_handshake_hashes_update */
                EXPECT_SUCCESS(s2n_conn_pre_handshake_hashes_update(conn));

                if (s2n_conn_get_current_message_type(conn) == CLIENT_FINISHED) {
                    /* check application secrets get updated in client finished */
                    EXPECT_BYTEARRAY_NOT_EQUAL(empty_secret.data, client_secrets.extract_secret.data, empty_secret.size);
                } else {
                    S2N_BLOB_EXPECT_EQUAL(empty_secret, client_secrets.extract_secret);
                }

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }
        }

        /* test that pre tls1.3 code paths are unaffected */
        for (int m = 0; m < s2n_array_len(modes); m++) {
            for (int i = 0; i < S2N_MAX_HANDSHAKE_LENGTH; i++) {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(modes[m]));

                conn->actual_protocol_version = S2N_TLS12;
                conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

                s2n_tls13_connection_keys(client_secrets, conn);
                S2N_BLOB_EXPECT_EQUAL(empty_secret, client_secrets.extract_secret);

                conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
                conn->handshake.message_number = i;

                /* trigger s2n_conn_pre_handshake_hashes_update */
                EXPECT_SUCCESS(s2n_conn_pre_handshake_hashes_update(conn));

                if (s2n_conn_get_current_message_type(conn) == CLIENT_FINISHED) {
                    /* check application secrets get updated in client finished */
                    S2N_BLOB_EXPECT_EQUAL(empty_secret, client_secrets.extract_secret);
                } else {
                    S2N_BLOB_EXPECT_EQUAL(empty_secret, client_secrets.extract_secret);
                }

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }
        }
    }

    /* Test: s2n_conn_post_handshake_hashes_update handlers */
    {
        S2N_BLOB_FROM_HEX(empty_secret, "0000000000000000000000000000000000000000000000000000000000000000");
        S2N_BLOB_FROM_HEX(ref_seq, "0100000000000000");
        S2N_BLOB_FROM_HEX(reset_seq, "0000000000000000");

        s2n_mode modes[] = { S2N_CLIENT, S2N_SERVER };

        /* we ensure this works in both client and server modes */
        for (int m = 0; m < s2n_array_len(modes); m++) {
            for (int i = 0; i < S2N_MAX_HANDSHAKE_LENGTH; i++) {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(modes[m]));
                EXPECT_NOT_NULL(conn->config);
                const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
                EXPECT_NOT_NULL(ecc_pref);

                conn->actual_protocol_version = S2N_TLS13;
                conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

                s2n_tls13_connection_keys(client_secrets, conn);
                S2N_BLOB_EXPECT_EQUAL(empty_secret, client_secrets.extract_secret);

                /* verify that that is the initial secret state */
                conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
                conn->handshake.message_number = i;

                conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
                conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_pref->ecc_curves[0];
                EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.server_ecc_evp_params));
                EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.client_ecc_evp_params[0]));

                struct s2n_blob client_seq = { .data = conn->secure.client_sequence_number,.size = sizeof(conn->secure.client_sequence_number) };
                struct s2n_blob server_seq = { .data = conn->secure.server_sequence_number,.size = sizeof(conn->secure.server_sequence_number) };
                client_seq.data[0] = 1;
                server_seq.data[0] = 1;

                EXPECT_SUCCESS(s2n_conn_post_handshake_hashes_update(conn));

                if (s2n_conn_get_current_message_type(conn) == SERVER_HELLO) {
                    /* prove secrets have been updated after ServerHello as they are no longer 0-filled byte arrays */
                    EXPECT_BYTEARRAY_NOT_EQUAL(empty_secret.data, client_secrets.extract_secret.data, empty_secret.size);
                } else {
                    S2N_BLOB_EXPECT_EQUAL(empty_secret, client_secrets.extract_secret);
                }

                if (s2n_conn_get_current_message_type(conn) == SERVER_HELLO || s2n_conn_get_current_message_type(conn) == CLIENT_FINISHED) {
                    S2N_BLOB_EXPECT_EQUAL(client_seq, reset_seq);
                    S2N_BLOB_EXPECT_EQUAL(server_seq, reset_seq);
                } else {
                    S2N_BLOB_EXPECT_EQUAL(client_seq, ref_seq);
                    S2N_BLOB_EXPECT_EQUAL(server_seq, ref_seq);
                }

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }
        }

        /* Test pre 1.3 code paths are unaffected */
        for (int m = 0; m < s2n_array_len(modes); m++) {
            for (int i = 0; i < S2N_MAX_HANDSHAKE_LENGTH; i++) {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(modes[m]));
                EXPECT_NOT_NULL(conn->config);
                const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
                EXPECT_NOT_NULL(ecc_pref);

                conn->actual_protocol_version = S2N_TLS12;
                conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

                s2n_tls13_connection_keys(client_secrets, conn);
                S2N_BLOB_EXPECT_EQUAL(empty_secret, client_secrets.extract_secret);

                /* verify that that is the initial secret state */
                conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
                conn->handshake.message_number = i;

                conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
                conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_pref->ecc_curves[0];
                EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.server_ecc_evp_params));
                EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.client_ecc_evp_params[0]));

                struct s2n_blob client_seq = { .data = conn->secure.client_sequence_number,.size = sizeof(conn->secure.client_sequence_number) };
                struct s2n_blob server_seq = { .data = conn->secure.server_sequence_number,.size = sizeof(conn->secure.server_sequence_number) };
                client_seq.data[0] = 1;
                server_seq.data[0] = 1;

                EXPECT_SUCCESS(s2n_conn_post_handshake_hashes_update(conn));

                if (s2n_conn_get_current_message_type(conn) == SERVER_HELLO) {
                    S2N_BLOB_EXPECT_EQUAL(empty_secret, client_secrets.extract_secret);
                } else {
                    S2N_BLOB_EXPECT_EQUAL(empty_secret, client_secrets.extract_secret);
                }

                if (s2n_conn_get_current_message_type(conn) == SERVER_HELLO || s2n_conn_get_current_message_type(conn) == CLIENT_FINISHED) {
                    S2N_BLOB_EXPECT_EQUAL(client_seq, ref_seq);
                    S2N_BLOB_EXPECT_EQUAL(server_seq, ref_seq);
                } else {
                    S2N_BLOB_EXPECT_EQUAL(client_seq, ref_seq);
                    S2N_BLOB_EXPECT_EQUAL(server_seq, ref_seq);
                }

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }
        }
    }

    /* Test: Handshake self-talks using s2n_handshake_write_io and s2n_handshake_read_io */
    {
        EXPECT_SUCCESS(s2n_enable_tls13());

        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;

        struct s2n_config *server_config, *client_config;
        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

        char *cert_chain = NULL;
        char *private_key = NULL;
        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));

        struct s2n_cert_chain_and_key *default_cert;
        EXPECT_NOT_NULL(default_cert = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(default_cert, cert_chain, private_key));
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
        EXPECT_EQUAL(server_conn->actual_protocol_version, 0);

        s2n_tls13_connection_keys(server_secrets_0, server_conn);
        EXPECT_EQUAL(server_secrets_0.size, 0);

        EXPECT_EQUAL(server_conn->handshake.handshake_type, INITIAL);

        /* Server reads ClientHello */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
        EXPECT_SUCCESS(s2n_handshake_read_io(server_conn));

        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13); /* Server is now on TLS13 */
        EXPECT_EQUAL(server_conn->handshake.handshake_type, NEGOTIATED | FULL_HANDSHAKE);

        s2n_tls13_connection_keys(server_secrets, server_conn);
        EXPECT_EQUAL(server_secrets.size, 48);

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

        /* Server sends ServerFinished */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_FINISHED);
        EXPECT_SUCCESS(s2n_handshake_write_io(server_conn));

        /* Client reads ServerHello */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
        EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

        /* Client reads CCS
         * The CCS message does not affect its place in the state machine. */
        EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), ENCRYPTED_EXTENSIONS);
        EXPECT_SUCCESS(s2n_handshake_read_io(client_conn));

        s2n_tls13_connection_keys(client_secrets, client_conn);
        EXPECT_EQUAL(client_secrets.size, 48);

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
