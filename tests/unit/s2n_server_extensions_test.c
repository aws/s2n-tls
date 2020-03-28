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

#include <s2n.h>

#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_server_supported_versions.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_ecc_preferences.h"

#include "utils/s2n_safety.h"

const uint8_t EXTENSION_LEN = 2;
const uint8_t SECURE_RENEGOTIATION_SIZE = 5;
const uint8_t NEW_SESSION_TICKET_SIZE = 4;

const uint8_t SUPPORTED_VERSION_SIZE = 6;
const uint8_t P256_KEYSHARE_SIZE = ( 32 * 2 ) + 1 + 8;
const uint8_t MIN_TLS13_EXTENSION_SIZE = ( 32 * 2 ) + 1 + 8 + 6; /* expanded from
                    P256_KEYSHARE_SIZE + SUPPORTED_VERSION_SIZE because gcc... */

/* set up minimum parameters for a tls13 connection so server extensions can work */
static int configure_tls13_connection(struct s2n_connection *conn)
{
    conn->actual_protocol_version = S2N_TLS13;
    const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
    conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
    conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_pref->ecc_curves[0];
    EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.client_ecc_evp_params[0]));
    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->handshake.io));

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_cert_chain_and_key *chain_and_key;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* s2n_server_extensions_send */
    {
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

        /* Test Server Extensions Send - No extensions */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), 0);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test Server Extensions Send - Server Name */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            /* server name size */
            const uint8_t size = 4;

            /* server name is sent when used */
            conn->server_name_used = 1;
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), size);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* server name is not sent when not used */
            conn->server_name_used = 0;
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), 0);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);

            /* TLS 1.3: server name extension is not sent here */
            EXPECT_SUCCESS(s2n_enable_tls13());
            EXPECT_SUCCESS(configure_tls13_connection(conn));
            conn->server_name_used = 1;
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), MIN_TLS13_EXTENSION_SIZE);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, MIN_TLS13_EXTENSION_SIZE + EXTENSION_LEN);
            EXPECT_SUCCESS(s2n_disable_tls13(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test Server Extensions Send - Application Protocol */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            strcpy(conn->application_protocol, "h2");
            const uint8_t application_protocol_len = strlen(conn->application_protocol);

            const uint8_t ALPN_LEN = 7 + application_protocol_len;
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), ALPN_LEN);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, ALPN_LEN + EXTENSION_LEN);

            strcpy(conn->application_protocol, "");
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), 0);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);

            /* TLS 1.3: extension is not sent here */
            EXPECT_SUCCESS(s2n_enable_tls13());
            EXPECT_SUCCESS(configure_tls13_connection(conn));
            strcpy(conn->application_protocol, "h2");
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), MIN_TLS13_EXTENSION_SIZE);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, MIN_TLS13_EXTENSION_SIZE + EXTENSION_LEN);
            EXPECT_SUCCESS(s2n_disable_tls13(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test Server Extensions Send - Maximum Fragment Length (MFL) */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            conn->mfl_code = 0;
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), 0);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);

            const uint8_t MFL_EXT_SIZE = 2 + 2 + 1;
            conn->mfl_code = S2N_TLS_MAX_FRAG_LEN_1024;
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), MFL_EXT_SIZE);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, MFL_EXT_SIZE + EXTENSION_LEN);

            /* TLS 1.3: extension is not sent here */
            EXPECT_SUCCESS(s2n_enable_tls13());
            EXPECT_SUCCESS(configure_tls13_connection(conn));
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), MIN_TLS13_EXTENSION_SIZE);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, MIN_TLS13_EXTENSION_SIZE + EXTENSION_LEN);
            EXPECT_SUCCESS(s2n_disable_tls13(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test Server Extensions Send - Signed Certificate Timestamp extension */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            struct s2n_cert_chain_and_key fake_chain_and_key = {0};
            static uint8_t sct_list[] = { 0xff, 0xff, 0xff };
            s2n_blob_init(&fake_chain_and_key.sct_list, sct_list, sizeof(sct_list));

            conn->ct_level_requested = S2N_CT_SUPPORT_REQUEST;
            conn->handshake_params.our_chain_and_key = &fake_chain_and_key;
            const uint8_t size = 4 + sizeof(sct_list);
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), size);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* TLS 1.3: extension is not sent here */
            EXPECT_SUCCESS(s2n_enable_tls13());
            EXPECT_SUCCESS(configure_tls13_connection(conn));
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), MIN_TLS13_EXTENSION_SIZE);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, MIN_TLS13_EXTENSION_SIZE + EXTENSION_LEN);
            EXPECT_SUCCESS(s2n_disable_tls13(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test Server Extensions Send - OCSP Status Request */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            struct s2n_cert_chain_and_key fake_chain_and_key = {0};
            static uint8_t fake_ocsp[] = { 0xff, 0xff, 0xff };
            s2n_blob_init(&fake_chain_and_key.ocsp_status, fake_ocsp, sizeof(fake_ocsp));

            conn->status_type = S2N_STATUS_REQUEST_OCSP;
            conn->handshake_params.our_chain_and_key = &fake_chain_and_key;

            const uint8_t size = 4;
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), size);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* TLS 1.3: extension is not sent here */
            EXPECT_SUCCESS(s2n_enable_tls13());
            EXPECT_SUCCESS(configure_tls13_connection(conn));
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), MIN_TLS13_EXTENSION_SIZE);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, MIN_TLS13_EXTENSION_SIZE + EXTENSION_LEN);
            EXPECT_SUCCESS(s2n_disable_tls13(conn));


            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test Server Extensions Send - Secure Negotiation */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            conn->secure_renegotiation = 1;
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), SECURE_RENEGOTIATION_SIZE);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, SECURE_RENEGOTIATION_SIZE + EXTENSION_LEN);

            conn->secure_renegotiation = 0;
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), 0);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test Server Extensions Send - New Session Ticket */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), 0);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);

            conn->config->use_tickets = 1;
            conn->session_ticket_status = S2N_NEW_TICKET;
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), NEW_SESSION_TICKET_SIZE);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, NEW_SESSION_TICKET_SIZE + EXTENSION_LEN);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test TLS13 Extensions */
        {
            EXPECT_SUCCESS(s2n_enable_tls13());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_NOT_NULL(conn->config);
            const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
            EXPECT_NOT_NULL(ecc_pref);
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

            /* Test that s2n_server_extensions_send() only works when protocol version is TLS13 */
            conn->actual_protocol_version = S2N_TLS13;

            /* key_share_send() requires a negotiated_curve */
            conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_pref->ecc_curves[0];

            const uint8_t size = P256_KEYSHARE_SIZE + SUPPORTED_VERSION_SIZE;

            EXPECT_EQUAL(s2n_extensions_server_supported_versions_size(conn), SUPPORTED_VERSION_SIZE);
            EXPECT_EQUAL(s2n_extensions_server_key_share_send_size(conn), P256_KEYSHARE_SIZE);

            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), size);
            EXPECT_FAILURE(s2n_server_extensions_send(conn, hello_stuffer));

            EXPECT_SUCCESS(s2n_stuffer_wipe(hello_stuffer));
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.client_ecc_evp_params[0]));

            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), size);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));

            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* Test that s2n_server_extensions_send() do not send extension < TLS13 */
            conn->actual_protocol_version = S2N_TLS12;

            s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer));
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), 0);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_disable_tls13());
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test Secure Negotiation server_hello extension not sent with TLS13 or higher */
        {
            EXPECT_SUCCESS(s2n_enable_tls13());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_NOT_NULL(conn->config);
            const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
            EXPECT_NOT_NULL(ecc_pref);
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            /* secure renegotiation is requested */
            conn->secure_renegotiation = 1;
            /* Test that s2n_server_extensions_send() only works when protocol version is TLS13 */
            conn->actual_protocol_version = S2N_TLS13;

            /* key_share_send() requires a negotiated_curve */
            conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_pref->ecc_curves[0];
            /* secure_renegotiation extension not send >=TLS13*/
            uint8_t size = s2n_extensions_server_key_share_send_size(conn)
                + s2n_extensions_server_supported_versions_size(conn);

            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), size);
            EXPECT_FAILURE(s2n_server_extensions_send(conn, hello_stuffer));

            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.client_ecc_evp_params[0]));

            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer)));
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), size);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));

            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* Only sending secure_renegotiation(if it is requested) < TLS13 */
            conn->actual_protocol_version = S2N_TLS12;
            uint8_t tls12_server_extension_size = SECURE_RENEGOTIATION_SIZE + EXTENSION_LEN;
            s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer));
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), SECURE_RENEGOTIATION_SIZE);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, tls12_server_extension_size);
            EXPECT_SUCCESS(s2n_disable_tls13());
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test New Session Ticket server_hello extension not sent with TLS13 or higher */
        {
            EXPECT_SUCCESS(s2n_enable_tls13());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_NOT_NULL(conn->config);
            const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
            EXPECT_NOT_NULL(ecc_pref);
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

            /* New Session Ticket Requested*/
            conn->config->use_tickets = 1;
            conn->session_ticket_status = S2N_NEW_TICKET;

            /* Test that s2n_server_extensions_send() only works when protocol version is TLS13 */
            conn->actual_protocol_version = S2N_TLS13;

            /* key_share_send() requires a negotiated_curve */
            conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_pref->ecc_curves[0];

            /* nst extension not send >=TLS13*/
            uint8_t size = s2n_extensions_server_key_share_send_size(conn)
                + s2n_extensions_server_supported_versions_size(conn)
            ;

            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), size);
            EXPECT_FAILURE(s2n_server_extensions_send(conn, hello_stuffer));

            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.client_ecc_evp_params[0]));

            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer)));
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), size);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));

            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* Sending nst (if it is requested) < TLS13 */
            conn->actual_protocol_version = S2N_TLS12;

            s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer));
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), NEW_SESSION_TICKET_SIZE);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            uint8_t tls12_server_extension_size = NEW_SESSION_TICKET_SIZE + EXTENSION_LEN;
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, tls12_server_extension_size);
            EXPECT_SUCCESS(s2n_disable_tls13());
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Test TLS13 Extensions with null key exchange alg cipher suites */
        {
            struct s2n_cipher_suite *tls12_cipher_suite = cipher_preferences_20170210.suites[cipher_preferences_20170210.count-1];
            uint8_t wire_ciphers_with_tls13[] = {
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                tls12_cipher_suite->iana_value[0], tls12_cipher_suite->iana_value[1]
            };
            const uint8_t cipher_count_tls13 = sizeof(wire_ciphers_with_tls13) / S2N_TLS_CIPHER_SUITE_LEN;

            EXPECT_SUCCESS(s2n_enable_tls13());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_NOT_NULL(conn->config);
            const struct s2n_ecc_preferences *ecc_pref = conn->config->ecc_preferences;
            EXPECT_NOT_NULL(ecc_pref);
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

            s2n_connection_set_cipher_preferences(conn, "test_all_tls13");
            /* Test that s2n_server_extensions_send() only works when protocol version is TLS13 */
            conn->client_protocol_version = S2N_TLS13;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_tls13, cipher_count_tls13));

            /* key_share_send() requires a negotiated_curve */
            conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_pref->ecc_curves[0];

            uint8_t size = s2n_extensions_server_key_share_send_size(conn)
                + s2n_extensions_server_supported_versions_size(conn);

            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), size);
            EXPECT_FAILURE(s2n_server_extensions_send(conn, hello_stuffer));

            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.client_ecc_evp_params[0]));

            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer)));
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), size);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));

            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* Test that s2n_server_extensions_send() do not send extension < TLS13 */
            conn->actual_protocol_version = S2N_TLS12;

            s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer));
            EXPECT_EQUAL(s2n_server_extensions_send_size(conn), 0);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_disable_tls13());
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        EXPECT_SUCCESS(s2n_config_free(config));
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

    END_TEST();
    return 0;
}
