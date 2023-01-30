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

#include "tls/s2n_server_extensions.h"

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_cert_status_response.h"
#include "tls/extensions/s2n_ec_point_format.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/extensions/s2n_server_psk.h"
#include "tls/extensions/s2n_server_supported_versions.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_bitmap.h"
#include "utils/s2n_safety.h"

const uint8_t EXTENSION_LEN = 2;
const uint8_t SECURE_RENEGOTIATION_SIZE = 5;
const uint8_t NEW_SESSION_TICKET_SIZE = 4;

const uint8_t SUPPORTED_VERSION_SIZE = 6;
const uint8_t P256_KEYSHARE_SIZE = (32 * 2) + 1 + 8;
const uint8_t MIN_TLS13_EXTENSION_SIZE = (32 * 2) + 1 + 8 + 6; /* expanded from
                    P256_KEYSHARE_SIZE + SUPPORTED_VERSION_SIZE because gcc... */

/* set up minimum parameters for a tls13 connection so server extensions can work */
static int configure_tls13_connection(struct s2n_connection *conn)
{
    conn->actual_protocol_version = S2N_TLS13;

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    EXPECT_NOT_NULL(ecc_pref);

    conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
    conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
    POSIX_GUARD(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->handshake.io));
    POSIX_GUARD(s2n_connection_allow_all_response_extensions(conn));

    return 0;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

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
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            EXPECT_EQUAL(s2n_stuffer_data_available(hello_stuffer), 0);
            EXPECT_SUCCESS(s2n_server_extensions_recv(conn, hello_stuffer));
            EXPECT_EQUAL(s2n_stuffer_data_available(hello_stuffer), 0);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test Server Extensions Send - Server Name */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            s2n_extension_type_id extension_id = 0;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_SERVER_NAME, &extension_id));
            S2N_CBIT_SET(conn->extension_requests_received, extension_id);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            /* server name size */
            const uint8_t size = 4;

            /* server name is sent when used */
            conn->server_name_used = 1;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* server name is not sent when not used */
            conn->server_name_used = 0;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);

            /* TLS 1.3: server name extension is not sent here */
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            EXPECT_SUCCESS(configure_tls13_connection(conn));
            conn->server_name_used = 1;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, MIN_TLS13_EXTENSION_SIZE + EXTENSION_LEN);
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test Server Extensions Send - Application Protocol */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            s2n_extension_type_id extension_id = 0;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_ALPN, &extension_id));
            S2N_CBIT_SET(conn->extension_requests_received, extension_id);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            strcpy(conn->application_protocol, "h2");
            const uint8_t application_protocol_len = strlen(conn->application_protocol);

            const uint8_t ALPN_LEN = 7 + application_protocol_len;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, ALPN_LEN + EXTENSION_LEN);

            strcpy(conn->application_protocol, "");
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);

            /* TLS 1.3: extension is not sent here */
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            EXPECT_SUCCESS(configure_tls13_connection(conn));
            strcpy(conn->application_protocol, "h2");
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, MIN_TLS13_EXTENSION_SIZE + EXTENSION_LEN);
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test Server Extensions Send - Maximum Fragment Length (MFL) */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            s2n_extension_type_id extension_id = 0;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_MAX_FRAG_LEN, &extension_id));
            S2N_CBIT_SET(conn->extension_requests_received, extension_id);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            conn->negotiated_mfl_code = 0;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);

            const uint8_t MFL_EXT_SIZE = 2 + 2 + 1;
            conn->negotiated_mfl_code = S2N_TLS_MAX_FRAG_LEN_1024;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, MFL_EXT_SIZE + EXTENSION_LEN);

            /* TLS 1.3: extension is not sent here */
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            EXPECT_SUCCESS(configure_tls13_connection(conn));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, MIN_TLS13_EXTENSION_SIZE + EXTENSION_LEN);
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test Server Extensions Send - Signed Certificate Timestamp extension */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            s2n_extension_type_id extension_id = 0;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_SCT_LIST, &extension_id));
            S2N_CBIT_SET(conn->extension_requests_received, extension_id);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            struct s2n_cert_chain_and_key fake_chain_and_key = { 0 };
            static uint8_t sct_list[] = { 0xff, 0xff, 0xff };
            s2n_blob_init(&fake_chain_and_key.sct_list, sct_list, sizeof(sct_list));

            conn->ct_level_requested = S2N_CT_SUPPORT_REQUEST;
            conn->handshake_params.our_chain_and_key = &fake_chain_and_key;
            const uint8_t size = 4 + sizeof(sct_list);
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* TLS 1.3: extension is not sent here */
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            EXPECT_SUCCESS(configure_tls13_connection(conn));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, MIN_TLS13_EXTENSION_SIZE + EXTENSION_LEN);
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test Server Extensions Send - OCSP Status Request */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            s2n_extension_type_id extension_id = 0;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_STATUS_REQUEST, &extension_id));
            S2N_CBIT_SET(conn->extension_requests_received, extension_id);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            struct s2n_cert_chain_and_key fake_chain_and_key = { 0 };
            static uint8_t fake_ocsp[] = { 0xff, 0xff, 0xff };
            s2n_blob_init(&fake_chain_and_key.ocsp_status, fake_ocsp, sizeof(fake_ocsp));

            conn->status_type = S2N_STATUS_REQUEST_OCSP;
            conn->handshake_params.our_chain_and_key = &fake_chain_and_key;

            const uint8_t size = 4;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* TLS 1.3: extension is not sent here */
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            EXPECT_SUCCESS(configure_tls13_connection(conn));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, MIN_TLS13_EXTENSION_SIZE + EXTENSION_LEN);
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test Server Extensions Send - Secure Negotiation */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            conn->secure_renegotiation = 1;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, SECURE_RENEGOTIATION_SIZE + EXTENSION_LEN);

            conn->secure_renegotiation = 0;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test Server Extensions Send - New Session Ticket */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            s2n_extension_type_id extension_id = 0;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_SESSION_TICKET, &extension_id));
            S2N_CBIT_SET(conn->extension_requests_received, extension_id);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;

            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);

            conn->config->use_tickets = 1;
            conn->session_ticket_status = S2N_NEW_TICKET;
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, NEW_SESSION_TICKET_SIZE + EXTENSION_LEN);
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test TLS13 Extensions */
        {
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_connection_allow_response_extension(conn, s2n_server_key_share_extension.iana_value));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

            /* Test that s2n_server_extensions_send() only works when protocol version is TLS13 */
            conn->actual_protocol_version = S2N_TLS13;

            /* key_share_send() requires a negotiated_curve */
            conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

            EXPECT_EQUAL(s2n_extensions_server_key_share_send_size(conn), P256_KEYSHARE_SIZE);

            EXPECT_FAILURE(s2n_server_extensions_send(conn, hello_stuffer));

            EXPECT_SUCCESS(s2n_stuffer_wipe(hello_stuffer));
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, P256_KEYSHARE_SIZE + EXTENSION_LEN);

            /* Test that s2n_server_extensions_send() do not send extension < TLS13 */
            conn->actual_protocol_version = S2N_TLS12;

            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer)));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test Secure Negotiation server_hello extension not sent with TLS13 or higher */
        {
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_connection_allow_response_extension(conn, s2n_server_key_share_extension.iana_value));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            /* secure renegotiation is requested */
            conn->secure_renegotiation = 1;
            /* Test that s2n_server_extensions_send() only works when protocol version is TLS13 */
            conn->actual_protocol_version = S2N_TLS13;

            /* key_share_send() requires a negotiated_curve */
            conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            /* secure_renegotiation extension not send >=TLS13*/
            uint8_t size = s2n_extensions_server_key_share_send_size(conn);

            EXPECT_FAILURE(s2n_server_extensions_send(conn, hello_stuffer));

            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer)));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* Only sending secure_renegotiation(if it is requested) < TLS13 */
            conn->actual_protocol_version = S2N_TLS12;
            uint8_t tls12_server_extension_size = SECURE_RENEGOTIATION_SIZE + EXTENSION_LEN;
            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer)));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, tls12_server_extension_size);
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test New Session Ticket server_hello extension not sent with TLS13 or higher */
        {
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            s2n_extension_type_id extension_id = 0;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_SESSION_TICKET, &extension_id));
            S2N_CBIT_SET(conn->extension_requests_received, extension_id);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_connection_allow_response_extension(conn, s2n_server_key_share_extension.iana_value));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

            /* New Session Ticket Requested*/
            conn->config->use_tickets = 1;
            conn->session_ticket_status = S2N_NEW_TICKET;

            /* Test that s2n_server_extensions_send() only works when protocol version is TLS13 */
            conn->actual_protocol_version = S2N_TLS13;

            /* key_share_send() requires a negotiated_curve */
            conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

            /* nst extension not send >=TLS13*/
            uint8_t size = s2n_extensions_server_key_share_send_size(conn);

            EXPECT_FAILURE(s2n_server_extensions_send(conn, hello_stuffer));

            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer)));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* Sending nst (if it is requested) < TLS13 */
            conn->actual_protocol_version = S2N_TLS12;

            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer)));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            uint8_t tls12_server_extension_size = NEW_SESSION_TICKET_SIZE + EXTENSION_LEN;
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, tls12_server_extension_size);
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test TLS13 Extensions with null key exchange alg cipher suites */
        {
            struct s2n_cipher_suite *tls12_cipher_suite = cipher_preferences_20170210.suites[cipher_preferences_20170210.count - 1];
            uint8_t wire_ciphers_with_tls13[] = {
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                tls12_cipher_suite->iana_value[0], tls12_cipher_suite->iana_value[1]
            };
            const uint8_t cipher_count_tls13 = sizeof(wire_ciphers_with_tls13) / S2N_TLS_CIPHER_SUITE_LEN;

            EXPECT_SUCCESS(s2n_enable_tls13_in_test());
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            EXPECT_SUCCESS(s2n_connection_allow_response_extension(conn, s2n_server_key_share_extension.iana_value));

            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all_tls13"));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);
            struct s2n_stuffer *hello_stuffer = &conn->handshake.io;
            conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

            /* Test that s2n_server_extensions_send() only works when protocol version is TLS13 */
            conn->client_protocol_version = S2N_TLS13;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_set_cipher_as_tls_server(conn, wire_ciphers_with_tls13, cipher_count_tls13));

            /* key_share_send() requires a negotiated_curve */
            conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

            uint8_t size = s2n_extensions_server_key_share_send_size(conn);

            EXPECT_FAILURE(s2n_server_extensions_send(conn, hello_stuffer));

            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer)));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, size + EXTENSION_LEN);

            /* Test that s2n_server_extensions_send() do not send extension < TLS13 */
            conn->actual_protocol_version = S2N_TLS12;

            EXPECT_SUCCESS(s2n_stuffer_skip_read(hello_stuffer, s2n_stuffer_data_available(hello_stuffer)));
            EXPECT_SUCCESS(s2n_server_extensions_send(conn, hello_stuffer));
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(hello_stuffer, 0);
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test that some TLS1.3 extensions (like PSK) not sent on a HRR request */
        {
            s2n_extension_type_id psk_extension_id = 0;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(s2n_server_psk_extension.iana_value, &psk_extension_id));

            struct s2n_psk psk = { 0 };

            for (size_t is_hrr = 0; is_hrr < 2; is_hrr++) {
                struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
                EXPECT_NOT_NULL(conn);
                EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));
                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));

                struct s2n_stuffer *io_stuffer = &conn->handshake.io;

                /* Setup required for PSK extension */
                conn->psk_params.chosen_psk = &psk;
                S2N_CBIT_CLR(conn->extension_requests_sent, psk_extension_id);
                EXPECT_TRUE(s2n_server_psk_extension.should_send(conn));

                /* Setup required for other server extensions */
                conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
                conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
                conn->kex_params.client_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp256r1;
                EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

                if (is_hrr) {
                    EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(conn));
                }

                EXPECT_SUCCESS(s2n_server_extensions_send(conn, io_stuffer));

                s2n_parsed_extensions_list parsed_extensions = { 0 };
                EXPECT_SUCCESS(s2n_extension_list_parse(io_stuffer, &parsed_extensions));

                bool psk_extension_sent = (parsed_extensions.parsed_extensions[psk_extension_id].extension_type
                        == s2n_server_psk_extension.iana_value);
                EXPECT_NOT_EQUAL(psk_extension_sent, is_hrr);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }
        };

        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Test ec_point_format extension */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha;

        struct s2n_stuffer stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        EXPECT_SUCCESS(s2n_server_extensions_send(conn, &stuffer));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));

        EXPECT_SUCCESS(s2n_server_extensions_send(conn, &stuffer));
        EXPECT_NOT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_server_extensions_recv(conn, &stuffer));
        EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);

        EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test supported_versions extension can change extensions processed.
     * In TLS1.2, we receive status_request on the ServerHello. TLS1.3 expects it on the Certificate. */
    {
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(server_conn));

        struct s2n_cert_chain_and_key fake_chain_and_key = { 0 };
        static uint8_t fake_ocsp[] = { 0xff, 0xff, 0xff };
        s2n_blob_init(&fake_chain_and_key.ocsp_status, fake_ocsp, sizeof(fake_ocsp));

        /* For our test status_request extension */
        server_conn->status_type = S2N_STATUS_REQUEST_OCSP;
        server_conn->handshake_params.our_chain_and_key = &fake_chain_and_key;

        /* supported_versions not included - should NOT use TLS1.3 extensions,
         * so should accept the status_request without issue. */
        {
            server_conn->actual_protocol_version = S2N_TLS12;
            server_conn->server_protocol_version = S2N_TLS12;

            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(client_conn));

            DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            /* Write extensions - just status_request */
            struct s2n_stuffer_reservation extension_list_size = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &extension_list_size));
            EXPECT_SUCCESS(s2n_extension_send(&s2n_cert_status_response_extension,
                    server_conn, &stuffer));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extension_list_size));

            EXPECT_EQUAL(client_conn->status_type, S2N_STATUS_REQUEST_NONE);
            EXPECT_EQUAL(client_conn->server_protocol_version, S2N_UNKNOWN_PROTOCOL_VERSION);
            EXPECT_SUCCESS(s2n_server_extensions_recv(client_conn, &stuffer));
            EXPECT_EQUAL(client_conn->status_type, S2N_STATUS_REQUEST_OCSP);
            EXPECT_EQUAL(client_conn->server_protocol_version, S2N_UNKNOWN_PROTOCOL_VERSION);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        };

        /* supported_versions included - should use TLS1.3 extensions,
         * so should reject the status_request bc it does not belong here. */
        {
            server_conn->actual_protocol_version = S2N_TLS13;
            server_conn->server_protocol_version = S2N_TLS13;

            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(client_conn));

            DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            /* Write extensions - supported_versions + status_request */
            struct s2n_stuffer_reservation extension_list_size = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &extension_list_size));
            EXPECT_SUCCESS(s2n_extension_send(&s2n_server_supported_versions_extension,
                    server_conn, &stuffer));
            EXPECT_SUCCESS(s2n_extension_send(&s2n_cert_status_response_extension,
                    server_conn, &stuffer));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extension_list_size));

            EXPECT_EQUAL(client_conn->status_type, S2N_STATUS_REQUEST_NONE);
            EXPECT_EQUAL(client_conn->server_protocol_version, S2N_UNKNOWN_PROTOCOL_VERSION);
            EXPECT_SUCCESS(s2n_server_extensions_recv(client_conn, &stuffer));
            EXPECT_EQUAL(client_conn->status_type, S2N_STATUS_REQUEST_NONE);
            EXPECT_EQUAL(client_conn->server_protocol_version, S2N_TLS13);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        };

        /* TLS1.3 HRR handshake - should use HRR TLS1.3 extensions,
         * so should reject the PSK extension  */
        {
            const uint8_t test_wire_index = 5;
            struct s2n_psk empty_psk = { 0 };

            server_conn->actual_protocol_version = S2N_TLS13;
            server_conn->server_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_conn_choose_state_machine(server_conn, S2N_TLS13));
            server_conn->psk_params.chosen_psk = &empty_psk;
            server_conn->psk_params.chosen_psk_wire_index = test_wire_index;

            DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            /* Write extensions - supported_versions + PSK */
            struct s2n_stuffer_reservation extension_list_size = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&stuffer, &extension_list_size));
            EXPECT_SUCCESS(s2n_extension_send(&s2n_server_supported_versions_extension,
                    server_conn, &stuffer));
            EXPECT_SUCCESS(s2n_extension_send(&s2n_server_psk_extension,
                    server_conn, &stuffer));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&extension_list_size));

            for (size_t is_hrr = 0; is_hrr < 2; is_hrr++) {
                struct s2n_connection *client_conn;
                EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
                EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(client_conn));
                client_conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_conn_choose_state_machine(client_conn, S2N_TLS13));

                EXPECT_SUCCESS(s2n_connection_mark_extension_received(client_conn, s2n_server_key_share_extension.iana_value));

                for (size_t i = 0; i <= test_wire_index; i++) {
                    struct s2n_psk *psk = NULL;
                    EXPECT_OK(s2n_array_pushback(&client_conn->psk_params.psk_list, (void **) &psk));
                }

                if (is_hrr) {
                    EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(client_conn));
                }

                EXPECT_EQUAL(client_conn->psk_params.chosen_psk_wire_index, 0);
                EXPECT_SUCCESS(s2n_server_extensions_recv(client_conn, &stuffer));

                if (is_hrr) {
                    EXPECT_EQUAL(client_conn->psk_params.chosen_psk_wire_index, 0);
                } else {
                    EXPECT_EQUAL(client_conn->psk_params.chosen_psk_wire_index, test_wire_index);
                }

                EXPECT_SUCCESS(s2n_connection_free(client_conn));
                EXPECT_SUCCESS(s2n_stuffer_reread(&stuffer));
            }
        };

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

    END_TEST();
    return 0;
}
