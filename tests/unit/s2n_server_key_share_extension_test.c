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

#include <stdint.h>

#include "api/s2n.h"
#include "pq-crypto/s2n_pq.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_nist_kats.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_bitmap.h"
#include "utils/s2n_safety.h"

#define HELLO_RETRY_MSG_NO 1

int s2n_server_key_share_send_check_pq_hybrid(struct s2n_connection *conn);
int s2n_server_key_share_send_check_ecdhe(struct s2n_connection *conn);
static int s2n_read_server_key_share_hybrid_test_vectors(const struct s2n_kem_group *kem_group, struct s2n_blob *pq_private_key,
        struct s2n_stuffer *pq_shared_secret, struct s2n_stuffer *key_share_payload);

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* Test s2n_server_key_share_send_check_ecdhe */
    {
        struct s2n_security_policy test_security_policy_no_x25519 = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &cipher_preferences_test_all_tls13,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .ecc_preferences = &s2n_ecc_preferences_20140601,
        };

        struct s2n_connection *conn = NULL;
        EXPECT_FAILURE(s2n_server_key_share_send_check_ecdhe(conn));

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->security_policy_override = &test_security_policy_no_x25519;

        EXPECT_FAILURE(s2n_server_key_share_send_check_ecdhe(conn));

        if (s2n_is_evp_apis_supported()) {
            conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_x25519;
            EXPECT_FAILURE(s2n_server_key_share_send_check_ecdhe(conn));
        }

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_send_check_ecdhe(conn), S2N_ERR_BAD_KEY_SHARE);

        conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_send_check_ecdhe(conn), S2N_ERR_BAD_KEY_SHARE);

        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));
        EXPECT_SUCCESS(s2n_server_key_share_send_check_ecdhe(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_extensions_server_key_share_send_size */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        EXPECT_EQUAL(0, s2n_extensions_server_key_share_send_size(conn));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        EXPECT_EQUAL(ecc_pref->ecc_curves[0]->share_size + 8, s2n_extensions_server_key_share_send_size(conn));

        conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[1];
        EXPECT_EQUAL(ecc_pref->ecc_curves[1]->share_size + 8, s2n_extensions_server_key_share_send_size(conn));

        conn->kex_params.server_ecc_evp_params.negotiated_curve = NULL;
        EXPECT_EQUAL(0, s2n_extensions_server_key_share_send_size(conn));

        /* A HelloRetryRequest only requires a Selected Group, not a key share */
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
        EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(conn));
        conn->kex_params.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
        EXPECT_EQUAL(6, s2n_extensions_server_key_share_send_size(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_server_key_share_extension.send sends key share success (ECDHE) */
    {
        struct s2n_connection *conn = NULL;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        EXPECT_NULL(conn->kex_params.server_kem_group_params.kem_group);
        DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

        for (size_t i = 0; i < ecc_pref->count; i++) {
            const struct s2n_ecc_named_curve *curve = ecc_pref->ecc_curves[i];
            conn->kex_params.server_ecc_evp_params.negotiated_curve = curve;
            conn->kex_params.client_ecc_evp_params.negotiated_curve = curve;
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

            EXPECT_SUCCESS(s2n_server_key_share_extension.send(conn, &stuffer));

            S2N_STUFFER_READ_EXPECT_EQUAL(&stuffer, curve->iana_id, uint16);
            S2N_STUFFER_READ_EXPECT_EQUAL(&stuffer, curve->share_size, uint16);
            S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(&stuffer, curve->share_size);
            EXPECT_NULL(conn->kex_params.server_kem_group_params.kem_group);
            EXPECT_EQUAL(conn->kex_params.server_ecc_evp_params.negotiated_curve, curve);
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&conn->kex_params.server_ecc_evp_params));
            EXPECT_SUCCESS(s2n_ecc_evp_params_free(&conn->kex_params.client_ecc_evp_params));
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_server_key_share_extension.send sends IANA ID for HRR (ECDHE) */
    {
        struct s2n_connection *conn = NULL;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
        conn->handshake.handshake_type = HELLO_RETRY_REQUEST;
        conn->handshake.message_number = HELLO_RETRY_MSG_NO;

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        EXPECT_NULL(conn->kex_params.server_kem_group_params.kem_group);
        DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

        for (size_t i = 0; i < ecc_pref->count; i++) {
            const struct s2n_ecc_named_curve *curve = ecc_pref->ecc_curves[i];
            conn->kex_params.server_ecc_evp_params.negotiated_curve = curve;
            EXPECT_NULL(conn->kex_params.server_ecc_evp_params.evp_pkey);

            EXPECT_SUCCESS(s2n_server_key_share_extension.send(conn, &stuffer));

            S2N_STUFFER_READ_EXPECT_EQUAL(&stuffer, curve->iana_id, uint16);
            EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));
            EXPECT_EQUAL(conn->kex_params.server_ecc_evp_params.negotiated_curve, curve);
            EXPECT_NULL(conn->kex_params.server_ecc_evp_params.evp_pkey);
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_server_key_share_extension.send for failures */
    {
        EXPECT_FAILURE(s2n_server_key_share_extension.send(NULL, NULL));

        struct s2n_connection *conn = NULL;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_FAILURE(s2n_server_key_share_extension.send(conn, NULL));

        DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

        /* Error if both curve and kem_group are NULL */
        conn->kex_params.server_ecc_evp_params.negotiated_curve = NULL;
        conn->kex_params.server_kem_group_params.kem_group = NULL;
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_extension.send(conn, &stuffer), S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_server_key_share_extension.recv with supported curves */
    {
        const struct s2n_ecc_preferences *ecc_pref = NULL;

        int i = 0;
        do {
            struct s2n_connection *server_send_conn;
            struct s2n_connection *client_recv_conn;
            EXPECT_NOT_NULL(server_send_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(client_recv_conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_send_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            struct s2n_stuffer *extension_stuffer = &server_send_conn->handshake.io;

            server_send_conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[i];
            server_send_conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[i];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_send_conn->kex_params.client_ecc_evp_params));
            EXPECT_SUCCESS(s2n_server_key_share_extension.send(server_send_conn, extension_stuffer));

            client_recv_conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[i];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_recv_conn->kex_params.client_ecc_evp_params));

            /* Parse key share */
            EXPECT_SUCCESS(s2n_server_key_share_extension.recv(client_recv_conn, extension_stuffer));
            EXPECT_EQUAL(s2n_stuffer_data_available(extension_stuffer), 0);

            EXPECT_EQUAL(server_send_conn->kex_params.server_ecc_evp_params.negotiated_curve->iana_id, client_recv_conn->kex_params.server_ecc_evp_params.negotiated_curve->iana_id);
            EXPECT_EQUAL(server_send_conn->kex_params.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[i]);

            EXPECT_SUCCESS(s2n_connection_free(server_send_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_recv_conn));

            i += 1;
        } while (i < ecc_pref->count);
    };

    /* Test s2n_server_key_share_extension.recv with various sample payloads */
    {
        /* valid extension payloads */
        if (s2n_is_evp_apis_supported()) {
            /* Payload values were generated by connecting to openssl */
            const char *key_share_payloads[] = {
                /* x25519 */
                "001d00206b24ffd795c496899cd14b7742a5ffbdc453c23085a7f82f0ed1e0296adb9e0e",
                /* p256 */
                "001700410474cfd75c0ab7b57247761a277e1c92b5810dacb251bb758f43e9d15aaf292c4a2be43e886425ba55653ebb7a4f32fe368bacce3df00c618645cf1eb646f22552",
                /* p384 */
                "00180061040a27264201368540483e97d324a3093e11a5862b0a1be0cf5d8510bc47ec285f5304e9ec3ba01a0c375c3b6fa4bd0ad44aae041bb776aebc7ee92462ad481fe86f8b6e3858d5c41d0f83b0404f711832a4119aec3da2eac86266f424b50aa212"
            };

            for (int i = 0; i < 3; i++) {
                struct s2n_stuffer extension_stuffer = { 0 };
                struct s2n_connection *client_conn;

                EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

                const struct s2n_ecc_preferences *ecc_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(client_conn, &ecc_pref));
                EXPECT_NOT_NULL(ecc_pref);

                const char *payload = key_share_payloads[i];

                EXPECT_NULL(client_conn->kex_params.server_ecc_evp_params.negotiated_curve);
                EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&extension_stuffer, payload));

                client_conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[i];
                EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_conn->kex_params.client_ecc_evp_params));

                EXPECT_SUCCESS(s2n_server_key_share_extension.recv(client_conn, &extension_stuffer));
                EXPECT_EQUAL(client_conn->kex_params.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[i]);
                EXPECT_EQUAL(s2n_stuffer_data_available(&extension_stuffer), 0);

                EXPECT_SUCCESS(s2n_stuffer_free(&extension_stuffer));
                EXPECT_SUCCESS(s2n_connection_free(client_conn));
            }

            /* Test that s2n_server_key_share_extension.recv is a no-op
             * if tls1.3 not enabled */
            {
                struct s2n_stuffer extension_stuffer = { 0 };
                struct s2n_connection *client_conn;

                EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

                EXPECT_SUCCESS(s2n_connection_allow_response_extension(client_conn, s2n_server_key_share_extension.iana_value));

                const struct s2n_ecc_preferences *ecc_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(client_conn, &ecc_pref));
                EXPECT_NOT_NULL(ecc_pref);

                const char *payload = key_share_payloads[0];

                EXPECT_NULL(client_conn->kex_params.server_ecc_evp_params.negotiated_curve);
                EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&extension_stuffer, payload));

                client_conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
                EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_conn->kex_params.client_ecc_evp_params));

                client_conn->actual_protocol_version = S2N_TLS12;
                EXPECT_SUCCESS(s2n_extension_recv(&s2n_server_key_share_extension, client_conn, &extension_stuffer));
                EXPECT_NULL(client_conn->kex_params.server_ecc_evp_params.negotiated_curve);
                EXPECT_NOT_EQUAL(s2n_stuffer_data_available(&extension_stuffer), 0);

                client_conn->actual_protocol_version = S2N_TLS13;
                EXPECT_SUCCESS(s2n_server_key_share_extension.recv(client_conn, &extension_stuffer));
                EXPECT_EQUAL(client_conn->kex_params.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[0]);
                EXPECT_EQUAL(s2n_stuffer_data_available(&extension_stuffer), 0);

                EXPECT_SUCCESS(s2n_stuffer_free(&extension_stuffer));
                EXPECT_SUCCESS(s2n_connection_free(client_conn));
            };
        }

        /* Test error handling parsing broken/trancated p256 key share */
        {
            struct s2n_stuffer extension_stuffer = { 0 };
            struct s2n_connection *client_conn;

            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            const char *p256 = "001700410474cfd75c0ab7b57247761a277e1c92b5810dacb251bb758f43e9d15aaf292c4a2be43e886425ba55653ebb7a4f32fe368bacce3df00c618645cf1eb6";

            EXPECT_NULL(client_conn->kex_params.server_ecc_evp_params.negotiated_curve);
            EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&extension_stuffer, p256));

            EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_extension.recv(client_conn, &extension_stuffer), S2N_ERR_BAD_KEY_SHARE);

            EXPECT_SUCCESS(s2n_stuffer_free(&extension_stuffer));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        };

        /* Test failure for receiving p256 key share for client configured p384 key share */
        {
            struct s2n_stuffer extension_stuffer = { 0 };
            struct s2n_connection *client_conn;

            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(client_conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            const char *p256 = "001700410474cfd75c0ab7b57247761a277e1c92b5810dacb251bb758f43e9d15aaf292c4a2be43e886425ba55653ebb7a4f32fe368bacce3df00c618645cf1eb646f22552";

            EXPECT_NULL(client_conn->kex_params.server_ecc_evp_params.negotiated_curve);
            EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&extension_stuffer, p256));

            /* If s2n_is_evp_apis_supported is not supported, the ecc_prefs->ecc_curves contains only p-256, p-384 curves. */
            int p_384_index = s2n_is_evp_apis_supported() ? 2 : 1;

            client_conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[p_384_index];
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_conn->kex_params.client_ecc_evp_params));

            EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_extension.recv(client_conn, &extension_stuffer), S2N_ERR_BAD_KEY_SHARE);

            EXPECT_SUCCESS(s2n_stuffer_free(&extension_stuffer));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        };
    };

    /* Test Shared Key Generation */
    {
        struct s2n_connection *client_conn, *server_conn;
        struct s2n_stuffer key_share_extension = { 0 };

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        server_conn->actual_protocol_version = S2N_TLS13;
        EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        EXPECT_SUCCESS(s2n_client_key_share_extension.send(client_conn, &key_share_extension));
        EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

        /* should read all data */
        EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

        /* Server configures the "negotiated_curve" */
        server_conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

        EXPECT_SUCCESS(s2n_server_key_share_extension.send(server_conn, &key_share_extension));
        EXPECT_SUCCESS(s2n_server_key_share_extension.recv(client_conn, &key_share_extension));
        EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

        EXPECT_EQUAL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve, client_conn->kex_params.server_ecc_evp_params.negotiated_curve);

        /* Ensure both client and server public key matches */
        s2n_public_ecc_keys_are_equal(&server_conn->kex_params.server_ecc_evp_params, &client_conn->kex_params.server_ecc_evp_params);
        s2n_public_ecc_keys_are_equal(&server_conn->kex_params.client_ecc_evp_params, &client_conn->kex_params.client_ecc_evp_params);

        /* Server generates shared key based on Server's Key and Client's public key  */
        struct s2n_blob server_shared_secret = { 0 };
        EXPECT_SUCCESS(s2n_ecc_evp_compute_shared_secret_from_params(
                &server_conn->kex_params.server_ecc_evp_params,
                &server_conn->kex_params.client_ecc_evp_params,
                &server_shared_secret));

        /* Clients generates shared key based on Client's Key and Server's public key */
        struct s2n_blob client_shared_secret = { 0 };
        EXPECT_SUCCESS(s2n_ecc_evp_compute_shared_secret_from_params(
                &client_conn->kex_params.client_ecc_evp_params,
                &client_conn->kex_params.server_ecc_evp_params,
                &client_shared_secret));

        /* Test that server shared secret matches client shared secret */
        if (ecc_pref->ecc_curves[0] == &s2n_ecc_curve_secp256r1 || ecc_pref->ecc_curves[0] == &s2n_ecc_curve_secp384r1) {
            /* Share sizes are described here: https://tools.ietf.org/html/rfc8446#section-4.2.8.2
             * and include the extra "legacy_form" byte */
            EXPECT_EQUAL(server_shared_secret.size, (ecc_pref->ecc_curves[0]->share_size - 1) * 0.5);
        } else {
            EXPECT_EQUAL(server_shared_secret.size, ecc_pref->ecc_curves[0]->share_size);
        }

        S2N_BLOB_EXPECT_EQUAL(server_shared_secret, client_shared_secret);

        EXPECT_SUCCESS(s2n_free(&client_shared_secret));
        EXPECT_SUCCESS(s2n_free(&server_shared_secret));

        /* Clean up */
        EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Test s2n_server_key_share_extension.send with supported curve not in s2n_ecc_preferences list selected */
    if (s2n_is_evp_apis_supported()) {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(conn->config);

        /* x25519 is supported by s2n, but NOT included in the 20140601 ecc_preferences list */
        const struct s2n_ecc_named_curve *test_curve = &s2n_ecc_curve_x25519;
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(conn->config, "20140601"));

        conn->kex_params.server_ecc_evp_params.negotiated_curve = test_curve;
        conn->kex_params.client_ecc_evp_params.negotiated_curve = test_curve;
        EXPECT_FAILURE(s2n_server_key_share_extension.send(conn, &conn->handshake.io));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test s2n_server_key_share_extension.recv with supported curve not in s2n_ecc_preferences list selected  */
    if (s2n_is_evp_apis_supported()) {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        struct s2n_stuffer *extension_stuffer = &conn->handshake.io;

        /* x25519 is supported by s2n, but NOT included in the 20140601 ecc_preferences list */
        const struct s2n_ecc_named_curve *test_curve = &s2n_ecc_curve_x25519;
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(conn->config, "20140601"));

        /* Write the iana id of x25519 as the group */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(extension_stuffer, test_curve->iana_id));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_extension.recv(conn, extension_stuffer),
                S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test the s2n_server_key_share_extension.recv with HelloRetryRequest */
    {
        EXPECT_SUCCESS(s2n_enable_tls13_in_test());
        /* For a HelloRetryRequest, we won't have a key share. We just have the server selected group/negotiated curve.
         * Test that s2n_server_key_share_extension.recv obtains the server negotiate curve successfully. */
        {
            struct s2n_connection *client_conn;
            struct s2n_connection *server_conn;

            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_stuffer *key_share_extension = &server_conn->handshake.io;

            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
            EXPECT_OK(s2n_conn_choose_state_machine(server_conn, S2N_TLS13));
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            server_conn->kex_params.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));
            EXPECT_MEMCPY_SUCCESS(server_conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
            EXPECT_SUCCESS(s2n_server_key_share_extension.send(server_conn, key_share_extension));

            const struct s2n_ecc_preferences *ecc_preferences = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_preferences));
            EXPECT_NOT_NULL(ecc_preferences);

            /* Verify that no key shares are sent */
            struct s2n_ecc_evp_params *ecc_evp_params = &server_conn->kex_params.client_ecc_evp_params;
            EXPECT_NULL(ecc_evp_params->negotiated_curve);
            EXPECT_NULL(ecc_evp_params->evp_pkey);

            /* Setup the client to have received a HelloRetryRequest */
            EXPECT_MEMCPY_SUCCESS(client_conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
            EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(client_conn, S2N_TLS13));
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(client_conn));
            EXPECT_SUCCESS(s2n_set_hello_retry_required(client_conn));

            /* Parse the key share */
            EXPECT_SUCCESS(s2n_server_key_share_extension.recv(client_conn, key_share_extension));
            EXPECT_EQUAL(s2n_stuffer_data_available(key_share_extension), 0);

            EXPECT_EQUAL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve, client_conn->kex_params.server_ecc_evp_params.negotiated_curve);
            EXPECT_NULL(client_conn->kex_params.server_ecc_evp_params.evp_pkey);

            EXPECT_SUCCESS(s2n_stuffer_free(key_share_extension));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        };
        EXPECT_SUCCESS(s2n_disable_tls13_in_test());
    };

    {
        /* KEM groups with Test Vectors defined in /tests/unit/kats/tls13_server_hybrid_key_share_recv.kat */
        const struct s2n_kem_group *test_kem_groups[] = {
            &s2n_secp256r1_kyber_512_r3,
#if EVP_APIS_SUPPORTED
            &s2n_x25519_kyber_512_r3,
#endif
        };

        const struct s2n_kem_preferences test_kem_prefs = {
            .kem_count = 0,
            .kems = NULL,
            .tls13_kem_group_count = s2n_array_len(test_kem_groups),
            .tls13_kem_groups = test_kem_groups,
            .tls13_pq_hybrid_draft_revision = 0
        };

        const struct s2n_security_policy test_security_policy = {
            .minimum_protocol_version = S2N_SSLv3,
            .cipher_preferences = &cipher_preferences_test_all_tls13,
            .kem_preferences = &test_kem_prefs,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        const struct s2n_kem_preferences test_all_supported_kem_prefs = {
            .kem_count = 0,
            .kems = NULL,
            .tls13_kem_group_count = S2N_SUPPORTED_KEM_GROUPS_COUNT,
            .tls13_kem_groups = ALL_SUPPORTED_KEM_GROUPS,
            .tls13_pq_hybrid_draft_revision = 0
        };

        const struct s2n_security_policy test_all_supported_kems_security_policy = {
            .minimum_protocol_version = S2N_SSLv3,
            .cipher_preferences = &cipher_preferences_test_all_tls13,
            .kem_preferences = &test_all_supported_kem_prefs,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        const struct s2n_kem_group *kem_groups_kyber[] = {
            &s2n_secp256r1_kyber_512_r3,
        };

        const struct s2n_kem_preferences kem_prefs_kyber = {
            .kem_count = 0,
            .kems = NULL,
            .tls13_kem_group_count = s2n_array_len(kem_groups_kyber),
            .tls13_kem_groups = kem_groups_kyber,
            .tls13_pq_hybrid_draft_revision = 0
        };

        const struct s2n_security_policy security_policy_kyber = {
            .minimum_protocol_version = S2N_SSLv3,
            .cipher_preferences = &cipher_preferences_test_all_tls13,
            .kem_preferences = &kem_prefs_kyber,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        /* Tests for s2n_server_key_share_extension.recv with hybrid PQ key shares */
        {
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());

            /* If PQ is disabled, the client will not have sent PQ IDs/keyshares in the ClientHello;
             * if the server responded with a PQ keyshare, we should error. */
            if (!s2n_pq_is_enabled()) {
                struct s2n_connection *client_conn = NULL;
                EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
                client_conn->security_policy_override = &test_security_policy;

                uint8_t iana_buffer[2];
                struct s2n_blob iana_blob = { 0 };
                struct s2n_stuffer iana_stuffer = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&iana_blob, iana_buffer, 2));
                EXPECT_SUCCESS(s2n_stuffer_init(&iana_stuffer, &iana_blob));
                EXPECT_SUCCESS(s2n_stuffer_write_uint16(&iana_stuffer, test_security_policy.kem_preferences->tls13_kem_groups[0]->iana_id));

                EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_extension.recv(client_conn, &iana_stuffer), S2N_ERR_PQ_DISABLED);

                EXPECT_SUCCESS(s2n_connection_free(client_conn));
            }

            /* Test s2n_server_key_share_extension.recv with KAT pq key shares */
            if (s2n_pq_is_enabled()) {
                {
                    for (size_t i = 0; i < s2n_array_len(test_kem_groups); i++) {
                        const struct s2n_kem_group *kem_group = test_kem_groups[i];
                        struct s2n_connection *client_conn = NULL;
                        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
                        client_conn->security_policy_override = &test_security_policy;

                        /* Read the test vectors from the KAT file (the PQ key shares are too long to hardcode inline).
                         * pq_private_key is intentionally missing DERFER_CLEANUP; it will get freed during s2n_connection_free. */
                        struct s2n_blob *pq_private_key = &client_conn->kex_params.client_kem_group_params.kem_params.private_key;
                        DEFER_CLEANUP(struct s2n_stuffer pq_shared_secret = { 0 }, s2n_stuffer_free);
                        DEFER_CLEANUP(struct s2n_stuffer key_share_payload = { 0 }, s2n_stuffer_free);
                        EXPECT_SUCCESS(s2n_read_server_key_share_hybrid_test_vectors(kem_group, pq_private_key,
                                &pq_shared_secret, &key_share_payload));

                        /* Assert correct initial state */
                        EXPECT_NULL(client_conn->kex_params.server_kem_group_params.kem_group);
                        EXPECT_NULL(client_conn->kex_params.client_kem_group_params.kem_group);

                        const struct s2n_kem_preferences *kem_prefs = NULL;
                        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(client_conn, &kem_prefs));
                        EXPECT_NOT_NULL(kem_prefs);
                        EXPECT_EQUAL(kem_group, kem_prefs->tls13_kem_groups[i]);

                        /* This set up would have been done when the client sent its key share(s) */
                        client_conn->kex_params.client_kem_group_params.kem_group = kem_group;
                        client_conn->kex_params.client_kem_group_params.ecc_params.negotiated_curve = kem_group->curve;
                        client_conn->kex_params.client_kem_group_params.kem_params.kem = kem_group->kem;
                        client_conn->kex_params.client_kem_group_params.kem_params.len_prefixed = true;
                        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_conn->kex_params.client_kem_group_params.ecc_params));

                        /* Call the function and assert correctness */
                        EXPECT_SUCCESS(s2n_server_key_share_extension.recv(client_conn, &key_share_payload));

                        EXPECT_NOT_NULL(client_conn->kex_params.server_kem_group_params.kem_group);
                        EXPECT_EQUAL(client_conn->kex_params.server_kem_group_params.kem_group, kem_group);
                        EXPECT_NOT_NULL(client_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
                        EXPECT_EQUAL(client_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve, kem_group->curve);
                        EXPECT_NOT_NULL(client_conn->kex_params.server_kem_group_params.kem_params.kem);
                        EXPECT_EQUAL(client_conn->kex_params.server_kem_group_params.kem_params.kem, kem_group->kem);

                        EXPECT_EQUAL(client_conn->kex_params.client_kem_group_params.kem_group, kem_group);
                        EXPECT_EQUAL(client_conn->kex_params.client_kem_group_params.ecc_params.negotiated_curve, kem_group->curve);
                        EXPECT_EQUAL(client_conn->kex_params.client_kem_group_params.kem_params.kem, kem_group->kem);
                        EXPECT_NOT_NULL(client_conn->kex_params.client_kem_group_params.kem_params.shared_secret.data);
                        EXPECT_EQUAL(client_conn->kex_params.client_kem_group_params.kem_params.shared_secret.size,
                                kem_group->kem->shared_secret_key_length);
                        EXPECT_BYTEARRAY_EQUAL(client_conn->kex_params.client_kem_group_params.kem_params.shared_secret.data,
                                pq_shared_secret.blob.data, kem_group->kem->shared_secret_key_length);

                        EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_payload), 0);

                        EXPECT_SUCCESS(s2n_connection_free(client_conn));
                    }
                };

                /* Test s2n_server_key_share_extension.recv with HRR for PQ */
                {
                    struct s2n_connection *client_conn = NULL;
                    EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
                    client_conn->security_policy_override = &test_security_policy;
                    client_conn->actual_protocol_version = S2N_TLS13;
                    EXPECT_OK(s2n_conn_choose_state_machine(client_conn, S2N_TLS13));
                    client_conn->handshake.handshake_type = HELLO_RETRY_REQUEST;
                    client_conn->handshake.message_number = HELLO_RETRY_MSG_NO;
                    client_conn->actual_protocol_version_established = 1;

                    /* In the HRR, the server indicated p256+Kyber as it's choice in the key share extension */
                    const struct s2n_kem_group *kem_group = &s2n_secp256r1_kyber_512_r3;
                    DEFER_CLEANUP(struct s2n_stuffer key_share_payload = { 0 }, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&key_share_payload, "2F3A"));

                    /* Client should successfully parse the indicated group */
                    EXPECT_SUCCESS(s2n_server_key_share_extension.recv(client_conn, &key_share_payload));

                    EXPECT_NOT_NULL(client_conn->kex_params.server_kem_group_params.kem_group);
                    EXPECT_EQUAL(client_conn->kex_params.server_kem_group_params.kem_group, kem_group);
                    EXPECT_NOT_NULL(client_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve);
                    EXPECT_EQUAL(client_conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve, kem_group->curve);
                    EXPECT_NOT_NULL(client_conn->kex_params.server_kem_group_params.kem_params.kem);
                    EXPECT_EQUAL(client_conn->kex_params.server_kem_group_params.kem_params.kem, kem_group->kem);

                    /* s2n_server_key_share_extension.recv should have exited early after parsing the indicated group,
                     * so everything else should be NULL */
                    EXPECT_NULL(client_conn->kex_params.client_kem_group_params.kem_group);
                    EXPECT_NULL(client_conn->kex_params.client_kem_group_params.ecc_params.negotiated_curve);
                    EXPECT_NULL(client_conn->kex_params.client_kem_group_params.ecc_params.evp_pkey);
                    EXPECT_NULL(client_conn->kex_params.client_kem_group_params.kem_params.kem);
                    EXPECT_NULL(client_conn->kex_params.client_kem_group_params.kem_params.private_key.data);
                    EXPECT_NULL(client_conn->kex_params.client_kem_group_params.kem_params.public_key.data);
                    EXPECT_NULL(client_conn->kex_params.client_kem_group_params.kem_params.shared_secret.data);

                    EXPECT_NULL(client_conn->kex_params.server_kem_group_params.ecc_params.evp_pkey);
                    EXPECT_NULL(client_conn->kex_params.server_kem_group_params.kem_params.shared_secret.data);

                    EXPECT_SUCCESS(s2n_connection_free(client_conn));
                };

                /* Various failure cases */
                {
                    for (size_t i = 0; i < s2n_array_len(test_kem_groups); i++) {
                        const struct s2n_kem_group *kem_group = test_kem_groups[i];
                        struct s2n_connection *client_conn;
                        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
                        client_conn->security_policy_override = &test_security_policy;

                        /* Server sends a named group identifier that isn't in the client's KEM preferences */
                        const char *bad_group = "2F2C"; /* IANA ID for secp256r1_threebears-babybear-r2 (not imported into s2n) */
                        DEFER_CLEANUP(struct s2n_stuffer bad_group_stuffer = { 0 }, s2n_stuffer_free);
                        EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&bad_group_stuffer, bad_group));
                        EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_extension.recv(client_conn, &bad_group_stuffer),
                                S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

                        /* Server sends a key share that is in the client's KEM preferences, but client didn't send a key share */
                        const char *wrong_share = "2F1F"; /* Full extension truncated - not necessary */
                        DEFER_CLEANUP(struct s2n_stuffer wrong_share_stuffer = { 0 }, s2n_stuffer_free);
                        EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&wrong_share_stuffer, wrong_share));
                        EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_extension.recv(client_conn, &wrong_share_stuffer),
                                S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

                        /* To test the remaining failure cases, we need to read in the test vector from the KAT file, then
                         * manipulate it as necessary. (We do this now, instead of earlier, because we needed
                         * client_kem_group_params[i].kem_params.private_key to be empty to test the previous case.) */
                        struct s2n_blob *pq_private_key = &client_conn->kex_params.client_kem_group_params.kem_params.private_key;
                        DEFER_CLEANUP(struct s2n_stuffer pq_shared_secret = { 0 }, s2n_stuffer_free);
                        DEFER_CLEANUP(struct s2n_stuffer key_share_payload = { 0 }, s2n_stuffer_free);
                        EXPECT_SUCCESS(s2n_read_server_key_share_hybrid_test_vectors(kem_group, pq_private_key,
                                &pq_shared_secret, &key_share_payload));

                        /* Server sends the wrong (total) size: data[2] and data[3] are the bytes containing the total size
                         * of the key share; bitflip data[2] to invalidate the sent size */
                        key_share_payload.blob.data[2] = ~key_share_payload.blob.data[2];
                        client_conn->kex_params.client_kem_group_params.kem_group = kem_group;
                        client_conn->kex_params.client_kem_group_params.ecc_params.negotiated_curve = kem_group->curve;
                        client_conn->kex_params.client_kem_group_params.kem_params.kem = kem_group->kem;
                        client_conn->kex_params.client_kem_group_params.kem_params.len_prefixed = true;
                        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_conn->kex_params.client_kem_group_params.ecc_params));
                        EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_extension.recv(client_conn, &key_share_payload),
                                S2N_ERR_BAD_KEY_SHARE);
                        /* Revert key_share_payload back to correct state */
                        key_share_payload.blob.data[2] = ~key_share_payload.blob.data[2];
                        EXPECT_SUCCESS(s2n_stuffer_reread(&key_share_payload));

                        /* Server sends the correct (total) size, but the extension doesn't contain all the data */
                        uint8_t truncated_extension[10];
                        EXPECT_MEMCPY_SUCCESS(truncated_extension, key_share_payload.blob.data, 10);
                        struct s2n_blob trunc_ext_blob = { 0 };
                        EXPECT_SUCCESS(s2n_blob_init(&trunc_ext_blob, truncated_extension, 10));
                        struct s2n_stuffer trunc_ext_stuffer = { 0 };
                        EXPECT_SUCCESS(s2n_stuffer_init(&trunc_ext_stuffer, &trunc_ext_blob));
                        EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_extension.recv(client_conn, &trunc_ext_stuffer),
                                S2N_ERR_BAD_KEY_SHARE);

                        /* Server sends the wrong ECC key share size: data[4] and data[5] are the two bytes containing
                         * the size of the ECC key share; bitflip data[4] to invalidate the size */
                        key_share_payload.blob.data[4] = ~key_share_payload.blob.data[4];
                        EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_extension.recv(client_conn, &key_share_payload),
                                S2N_ERR_BAD_KEY_SHARE);
                        /* Revert key_share_payload back to correct state */
                        key_share_payload.blob.data[4] = ~key_share_payload.blob.data[4];
                        EXPECT_SUCCESS(s2n_stuffer_reread(&key_share_payload));

                        /* Server sends the wrong PQ share size size: index of the first byte of the size of the PQ key share
                         * depends of how large the ECC key share is */
                        size_t pq_share_size_index =
                                S2N_SIZE_OF_NAMED_GROUP
                                + S2N_SIZE_OF_KEY_SHARE_SIZE /* Not a typo; PQ shares have an overall (combined) size */
                                + S2N_SIZE_OF_KEY_SHARE_SIZE /* and a size for each contribution of the hybrid share. */
                                + kem_group->curve->share_size;
                        key_share_payload.blob.data[pq_share_size_index] = ~key_share_payload.blob.data[pq_share_size_index];
                        EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_extension.recv(client_conn, &key_share_payload),
                                S2N_ERR_BAD_KEY_SHARE);
                        /* Revert key_share_payload back to correct state */
                        key_share_payload.blob.data[pq_share_size_index] = ~key_share_payload.blob.data[pq_share_size_index];
                        EXPECT_SUCCESS(s2n_stuffer_reread(&key_share_payload));

                        /* Server sends a bad PQ key share (ciphertext): in order to guarantee certain crypto properties,
                         * the PQ KEM decapsulation functions are written so that the decaps will succeed without error
                         * in this case, but the returned PQ shared secret will be incorrect. In practice, this means
                         * that the key_share.recv function will succeed, but the overall handshake will fail later when
                         * client+server attempt to use the (different) shared secrets they each derived. */
                        size_t pq_key_share_first_byte_index = pq_share_size_index + 2;
                        key_share_payload.blob.data[pq_key_share_first_byte_index] = ~key_share_payload.blob.data[pq_key_share_first_byte_index];
                        EXPECT_SUCCESS(s2n_server_key_share_extension.recv(client_conn, &key_share_payload));
                        EXPECT_BYTEARRAY_NOT_EQUAL(client_conn->kex_params.client_kem_group_params.kem_params.shared_secret.data,
                                pq_shared_secret.blob.data, kem_group->kem->shared_secret_key_length);

                        EXPECT_SUCCESS(s2n_connection_free(client_conn));
                    }
                };
            }
            EXPECT_SUCCESS(s2n_disable_tls13_in_test());
        };

        /* Test s2n_server_key_share_send_check_pq_hybrid */
        {
            struct s2n_connection *conn = NULL;
            EXPECT_FAILURE(s2n_server_key_share_send_check_pq_hybrid(conn));

            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            if (!s2n_pq_is_enabled()) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_send_check_pq_hybrid(conn), S2N_ERR_PQ_DISABLED);
            }

            if (s2n_pq_is_enabled()) {
                conn->security_policy_override = &security_policy_kyber;

                EXPECT_FAILURE(s2n_server_key_share_send_check_pq_hybrid(conn));
                conn->kex_params.server_kem_group_params.kem_params.kem = &s2n_kyber_512_r3;

                EXPECT_FAILURE(s2n_server_key_share_send_check_pq_hybrid(conn));
                conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve = &s2n_ecc_curve_secp256r1;

                conn->kex_params.server_kem_group_params.kem_group = &s2n_secp256r1_kyber_512_r3;
                EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_send_check_pq_hybrid(conn), S2N_ERR_BAD_KEY_SHARE);

                conn->kex_params.server_kem_group_params.kem_group = &s2n_secp256r1_kyber_512_r3;
                conn->kex_params.server_kem_group_params.kem_params.kem = &s2n_kyber_512_r3;
                EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_send_check_pq_hybrid(conn), S2N_ERR_BAD_KEY_SHARE);

                conn->kex_params.client_kem_group_params.kem_group = &s2n_secp256r1_kyber_512_r3;
                EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_send_check_pq_hybrid(conn), S2N_ERR_BAD_KEY_SHARE);

                conn->kex_params.client_kem_group_params.ecc_params.negotiated_curve = s2n_secp256r1_kyber_512_r3.curve;
                EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_send_check_pq_hybrid(conn), S2N_ERR_BAD_KEY_SHARE);

                EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_kem_group_params.ecc_params));
                EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_send_check_pq_hybrid(conn), S2N_ERR_BAD_KEY_SHARE);

                conn->kex_params.client_kem_group_params.kem_params.kem = s2n_secp256r1_kyber_512_r3.kem;
                EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_send_check_pq_hybrid(conn), S2N_ERR_BAD_KEY_SHARE);

                EXPECT_SUCCESS(s2n_alloc(&conn->kex_params.client_kem_group_params.kem_params.public_key,
                        s2n_secp256r1_kyber_512_r3.kem->public_key_length));
                EXPECT_OK(s2n_kem_generate_keypair(&conn->kex_params.client_kem_group_params.kem_params));
                EXPECT_SUCCESS(s2n_server_key_share_send_check_pq_hybrid(conn));
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test s2n_server_key_share_extension.send sends key share success (PQ) */
        if (s2n_pq_is_enabled()) {
            for (int len_prefixed = 0; len_prefixed < 2; len_prefixed++) {
                for (size_t i = 0; i < S2N_SUPPORTED_KEM_GROUPS_COUNT; i++) {
                    struct s2n_connection *conn = NULL;
                    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
                    conn->security_policy_override = &test_all_supported_kems_security_policy;

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);

                    DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 4096));

                    /* Set up the server so that it's chosen the correct KEM group and received
                     * a correspond keyshare from client */
                    conn->kex_params.server_ecc_evp_params.negotiated_curve = NULL;

                    struct s2n_kem_group_params *server_params = &conn->kex_params.server_kem_group_params;
                    const struct s2n_kem_group *kem_group = kem_pref->tls13_kem_groups[i];
                    server_params->kem_group = kem_group;
                    server_params->kem_params.kem = kem_group->kem;
                    server_params->ecc_params.negotiated_curve = kem_group->curve;

                    struct s2n_kem_group_params *client_params = &conn->kex_params.client_kem_group_params;
                    client_params->kem_group = kem_group;
                    client_params->kem_params.kem = kem_group->kem;
                    client_params->kem_params.len_prefixed = (bool) len_prefixed; /* This would normally be auto-detected when receiving the Client's KeyShare*/
                    client_params->ecc_params.negotiated_curve = kem_group->curve;

                    EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params->ecc_params));
                    EXPECT_SUCCESS(s2n_alloc(&client_params->kem_params.public_key, kem_group->kem->public_key_length));
                    EXPECT_OK(s2n_kem_generate_keypair(&client_params->kem_params));
                    EXPECT_SUCCESS(s2n_server_key_share_extension.send(conn, &stuffer));
                    uint16_t expected_hybrid_share_size = kem_group->curve->share_size + kem_group->kem->ciphertext_length;

                    if (client_params->kem_params.len_prefixed) {
                        expected_hybrid_share_size += (2 * S2N_SIZE_OF_KEY_SHARE_SIZE);
                    }

                    /*  IANA ID (2 bytes) + total share size (2 bytes) + Hybrid Share */
                    EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), ((2 * sizeof(uint16_t)) + expected_hybrid_share_size));

                    /* Assert we sent a hybrid key share */
                    S2N_STUFFER_READ_EXPECT_EQUAL(&stuffer, kem_group->iana_id, uint16);
                    S2N_STUFFER_READ_EXPECT_EQUAL(&stuffer, expected_hybrid_share_size, uint16);

                    if (len_prefixed) {
                        S2N_STUFFER_READ_EXPECT_EQUAL(&stuffer, kem_group->curve->share_size, uint16);
                    }
                    EXPECT_SUCCESS(s2n_stuffer_skip_read(&stuffer, kem_group->curve->share_size));

                    if (len_prefixed) {
                        S2N_STUFFER_READ_EXPECT_EQUAL(&stuffer, kem_group->kem->ciphertext_length, uint16);
                    }
                    S2N_STUFFER_LENGTH_WRITTEN_EXPECT_EQUAL(&stuffer, kem_group->kem->ciphertext_length);

                    EXPECT_NULL(conn->kex_params.server_ecc_evp_params.negotiated_curve);
                    EXPECT_EQUAL(server_params->kem_group, kem_group);
                    EXPECT_EQUAL(server_params->kem_params.kem, kem_group->kem);
                    EXPECT_EQUAL(server_params->ecc_params.negotiated_curve, kem_group->curve);
                    EXPECT_EQUAL(client_params->kem_params.shared_secret.size, kem_group->kem->shared_secret_key_length);
                    EXPECT_NOT_NULL(client_params->kem_params.shared_secret.data);

                    EXPECT_SUCCESS(s2n_connection_free(conn));
                }
            }
        }

        /* Test s2n_server_key_share_extension.send sends IANA ID for HRR (PQ) */
        {
            struct s2n_connection *conn = NULL;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->security_policy_override = &test_all_supported_kems_security_policy;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
            conn->handshake.handshake_type = HELLO_RETRY_REQUEST;
            conn->handshake.message_number = HELLO_RETRY_MSG_NO;

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);

            EXPECT_NULL(conn->kex_params.server_ecc_evp_params.negotiated_curve);
            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 1024));

            for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
                struct s2n_kem_group_params *server_params = &conn->kex_params.server_kem_group_params;
                const struct s2n_kem_group *kem_group = kem_pref->tls13_kem_groups[i];

                server_params->kem_group = kem_group;
                server_params->kem_params.kem = kem_group->kem;
                server_params->ecc_params.negotiated_curve = kem_group->curve;
                EXPECT_NULL(conn->kex_params.server_ecc_evp_params.evp_pkey);
                EXPECT_NULL(conn->kex_params.server_ecc_evp_params.negotiated_curve);

                EXPECT_SUCCESS(s2n_server_key_share_extension.send(conn, &stuffer));

                S2N_STUFFER_READ_EXPECT_EQUAL(&stuffer, kem_group->iana_id, uint16);
                EXPECT_EQUAL(0, s2n_stuffer_data_available(&stuffer));

                EXPECT_EQUAL(server_params->kem_group, kem_group);
                EXPECT_EQUAL(server_params->kem_params.kem, kem_group->kem);
                EXPECT_EQUAL(server_params->ecc_params.negotiated_curve, kem_group->curve);
                EXPECT_NULL(server_params->kem_params.shared_secret.data);
                EXPECT_EQUAL(0, server_params->kem_params.shared_secret.size);
                EXPECT_NULL(server_params->ecc_params.evp_pkey);

                EXPECT_NULL(conn->kex_params.server_ecc_evp_params.negotiated_curve);
                EXPECT_NULL(conn->kex_params.server_ecc_evp_params.evp_pkey);
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test s2n_server_key_share_extension.send fails when both server_kem_group and server_curve are non-NULL */
        {
            struct s2n_connection *conn = NULL;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->security_policy_override = &test_all_supported_kems_security_policy;

            const struct s2n_kem_preferences *kem_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
            EXPECT_NOT_NULL(kem_pref);

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->kex_params.server_kem_group_params.kem_group = kem_pref->tls13_kem_groups[0];

            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_share_extension.send(conn, &stuffer), S2N_ERR_ECDHE_UNSUPPORTED_CURVE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    END_TEST();
    return 0;
}

static int s2n_read_server_key_share_hybrid_test_vectors(const struct s2n_kem_group *kem_group, struct s2n_blob *pq_private_key,
        struct s2n_stuffer *pq_shared_secret, struct s2n_stuffer *key_share_payload)
{
    FILE *kat_file = fopen("kats/tls13_server_hybrid_key_share_recv.kat", "r");
    POSIX_ENSURE_REF(kat_file);

    /* 50 should be plenty big enough to hold the entire marker string */
    char marker[50] = "kem_group = ";
    strcat(marker, kem_group->name);
    POSIX_GUARD(FindMarker(kat_file, marker));

    POSIX_GUARD(s2n_alloc(pq_private_key, kem_group->kem->private_key_length));
    POSIX_GUARD(ReadHex(kat_file, pq_private_key->data, kem_group->kem->private_key_length, "pq_private_key = "));
    pq_private_key->size = kem_group->kem->private_key_length;

    POSIX_GUARD(s2n_stuffer_alloc(pq_shared_secret, kem_group->kem->shared_secret_key_length));
    uint8_t *pq_shared_secret_ptr = s2n_stuffer_raw_write(pq_shared_secret, kem_group->kem->shared_secret_key_length);
    POSIX_ENSURE_REF(pq_shared_secret_ptr);
    POSIX_GUARD(ReadHex(kat_file, pq_shared_secret_ptr, kem_group->kem->shared_secret_key_length, "pq_shared_secret = "));

    size_t key_share_payload_size =
            S2N_SIZE_OF_NAMED_GROUP
            + S2N_SIZE_OF_KEY_SHARE_SIZE /* Not a typo; PQ shares have an overall (combined) size */
            + S2N_SIZE_OF_KEY_SHARE_SIZE /* and a size for each contribution of the hybrid share. */
            + kem_group->curve->share_size
            + S2N_SIZE_OF_KEY_SHARE_SIZE
            + kem_group->kem->ciphertext_length;

    POSIX_GUARD(s2n_stuffer_alloc(key_share_payload, key_share_payload_size));
    uint8_t *key_share_payload_ptr = s2n_stuffer_raw_write(key_share_payload, key_share_payload_size);
    POSIX_ENSURE_REF(key_share_payload_ptr);
    POSIX_GUARD(ReadHex(kat_file, key_share_payload_ptr, key_share_payload_size, "server_key_share_payload = "));

    fclose(kat_file);
    return S2N_SUCCESS;
}
