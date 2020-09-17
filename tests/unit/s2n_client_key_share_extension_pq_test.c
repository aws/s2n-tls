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

#include <stdint.h>

#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/extensions/s2n_key_share.h"
#include "tls/s2n_security_policies.h"

#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"
#include "crypto/s2n_fips.h"

#define HELLO_RETRY_MSG_NO 1

#if defined(S2N_NO_PQ)

int main() {
    BEGIN_TEST();
    END_TEST();
    return 0;
}

#else

static int s2n_generate_pq_hybrid_key_share_for_test(struct s2n_stuffer *out, struct s2n_kem_group_params *kem_group_params);
static int s2n_copy_pq_share(struct s2n_stuffer *from, struct s2n_blob *to, const struct s2n_kem_group *kem_group);

int main() {
    BEGIN_TEST();
    /* PQ hybrid tests for s2n_client_key_share_extension */
    {
        const struct s2n_kem_group *all_kem_groups[] = {
                &s2n_secp256r1_sike_p434_r2,
                &s2n_secp256r1_bike1_l1_r2,
                &s2n_secp256r1_kyber_512_r2,
#if EVP_APIS_SUPPORTED
                &s2n_x25519_sike_p434_r2,
                &s2n_x25519_bike1_l1_r2,
                &s2n_x25519_kyber_512_r2,
#endif
        };

        const struct s2n_kem_preferences kem_prefs_all = {
                .kem_count = 0,
                .kems = NULL,
                .tls13_kem_group_count = s2n_array_len(all_kem_groups),
                .tls13_kem_groups = all_kem_groups,
        };

        const struct s2n_security_policy security_policy_all = {
                .minimum_protocol_version = S2N_SSLv3,
                .cipher_preferences = &cipher_preferences_test_all_tls13,
                .kem_preferences = &kem_prefs_all,
                .signature_preferences = &s2n_signature_preferences_20200207,
                .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        const struct s2n_kem_group *kem_groups_sike[] = {
                &s2n_secp256r1_sike_p434_r2,
        };
        const struct s2n_kem_preferences kem_prefs_sike = {
                .kem_count = 0,
                .kems = NULL,
                .tls13_kem_group_count = s2n_array_len(kem_groups_sike),
                .tls13_kem_groups = kem_groups_sike,
        };

        const struct s2n_security_policy security_policy_sike = {
                .minimum_protocol_version = S2N_SSLv3,
                .cipher_preferences = &cipher_preferences_test_all_tls13,
                .kem_preferences = &kem_prefs_sike,
                .signature_preferences = &s2n_signature_preferences_20200207,
                .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        EXPECT_EQUAL(S2N_SUPPORTED_KEM_GROUPS_COUNT, s2n_array_len(all_kem_groups));

        /* Tests for s2n_client_key_share_extension.send */
        {
            /* Test that s2n_client_key_share_extension.send sends only ECC key shares
             * when in FIPS mode, even if tls13_kem_groups is non-null. */
            if (s2n_is_in_fips_mode()) {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                conn->security_policy_override = &security_policy_all;

                const struct s2n_kem_preferences *kem_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
                EXPECT_NOT_NULL(kem_pref);
                EXPECT_EQUAL(kem_pref->tls13_kem_group_count, S2N_SUPPORTED_KEM_GROUPS_COUNT);

                const struct s2n_ecc_preferences *ecc_preferences = NULL;
                EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
                EXPECT_NOT_NULL(ecc_preferences);

                DEFER_CLEANUP(struct s2n_stuffer key_share_extension = {0}, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 1024));
                EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

                /* Assert total key shares extension size is correct */
                uint16_t sent_key_shares_size;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_key_shares_size));
                EXPECT_EQUAL(sent_key_shares_size, s2n_stuffer_data_available(&key_share_extension));

                /* ECC key shares should have the format: IANA ID || size || share. Only one ECC key share
                 * should be sent (as per default s2n behavior). */
                uint16_t iana_value, share_size;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
                EXPECT_EQUAL(iana_value, ecc_preferences->ecc_curves[0]->iana_id);
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
                EXPECT_EQUAL(share_size, ecc_preferences->ecc_curves[0]->share_size);
                EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, share_size));

                /* If all the sizes/bytes were correctly written, there should be nothing left over */
                EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            }

            /* Test that s2n_client_key_share_extension.send generates and sends PQ hybrid
             * and ECC shares correctly when not in FIPS mode. */
            if (!s2n_is_in_fips_mode()) {
                for (size_t i = 0; i < S2N_SUPPORTED_KEM_GROUPS_COUNT; i++) {
                    /* The PQ hybrid key share send function only sends the highest priority PQ key share. On each
                     * iteration of the outer loop of this test (index i), we populate test_kem_groups[] with a
                     * different permutation of all_kem_groups[] to ensure we handle each kem_group key share
                     * correctly. */
                    const struct s2n_kem_group *test_kem_groups[S2N_SUPPORTED_KEM_GROUPS_COUNT];
                    for (size_t j = 0; j < S2N_SUPPORTED_KEM_GROUPS_COUNT; j++) {
                        test_kem_groups[j] = all_kem_groups[(j + i) % S2N_SUPPORTED_KEM_GROUPS_COUNT];
                    }

                    const struct s2n_kem_preferences test_kem_prefs = {
                            .kem_count = 0,
                            .kems = NULL,
                            .tls13_kem_group_count = s2n_array_len(test_kem_groups),
                            .tls13_kem_groups = test_kem_groups,
                    };

                    const struct s2n_security_policy test_security_policy = {
                            .minimum_protocol_version = S2N_SSLv3,
                            .cipher_preferences = &cipher_preferences_test_all_tls13,
                            .kem_preferences = &test_kem_prefs,
                            .signature_preferences = &s2n_signature_preferences_20200207,
                            .ecc_preferences = &s2n_ecc_preferences_20200310,
                    };

                    /* Test sending of default hybrid key share (non-HRR) */
                    {
                        struct s2n_connection *conn;
                        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                        conn->security_policy_override = &test_security_policy;

                        const struct s2n_ecc_preferences *ecc_pref = NULL;
                        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
                        EXPECT_NOT_NULL(ecc_pref);

                        const struct s2n_kem_preferences *kem_pref = NULL;
                        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
                        EXPECT_NOT_NULL(kem_pref);
                        EXPECT_EQUAL(kem_pref->tls13_kem_group_count, S2N_SUPPORTED_KEM_GROUPS_COUNT);
                        EXPECT_EQUAL(test_kem_groups[0], kem_pref->tls13_kem_groups[0]);
                        const struct s2n_kem_group *test_kem_group = kem_pref->tls13_kem_groups[0];

                        DEFER_CLEANUP(struct s2n_stuffer key_share_extension = {0}, s2n_stuffer_free);
                        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 4096));
                        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

                        /* First, assert that the client saved its private keys correctly in the connection state
                         * for both hybrid PQ and classic ECC */
                        struct s2n_kem_group_params *kem_group_params = &conn->secure.client_kem_group_params[0];
                        EXPECT_EQUAL(kem_group_params->kem_group, test_kem_group);
                        EXPECT_EQUAL(kem_group_params->kem_params.kem, test_kem_group->kem);
                        EXPECT_NOT_NULL(kem_group_params->kem_params.private_key.data);
                        EXPECT_EQUAL(kem_group_params->kem_params.private_key.size,test_kem_group->kem->private_key_length);
                        EXPECT_EQUAL(kem_group_params->ecc_params.negotiated_curve, test_kem_group->curve);
                        EXPECT_NOT_NULL(kem_group_params->ecc_params.evp_pkey);

                        struct s2n_ecc_evp_params *ecc_params = &conn->secure.client_ecc_evp_params[0];
                        EXPECT_EQUAL(ecc_params->negotiated_curve, ecc_pref->ecc_curves[0]);
                        EXPECT_NOT_NULL(ecc_params->evp_pkey);

                        /* Next, assert that the client didn't generate/save any hybrid or ECC params that it shouldn't have */
                        for (size_t kem_group_index = 1;
                             kem_group_index < S2N_SUPPORTED_KEM_GROUPS_COUNT; kem_group_index++) {
                            EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].kem_group);
                            EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].kem_params.kem);
                            EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].kem_params.private_key.data);
                            EXPECT_EQUAL(conn->secure.client_kem_group_params[kem_group_index].kem_params.private_key.size,0);
                            EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].ecc_params.negotiated_curve);
                            EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].ecc_params.evp_pkey);
                        }
                        for (size_t ecc_index = 1; ecc_index < S2N_ECC_EVP_SUPPORTED_CURVES_COUNT; ecc_index++) {
                            EXPECT_NULL(conn->secure.client_ecc_evp_params[ecc_index].negotiated_curve);
                            EXPECT_NULL(conn->secure.client_ecc_evp_params[ecc_index].evp_pkey);
                        }

                        /* Now, assert that the client sent the correct bytes over the wire for the key share extension */
                        /* Assert total key shares extension size is correct */
                        uint16_t sent_key_shares_size;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_key_shares_size));
                        EXPECT_EQUAL(sent_key_shares_size, s2n_stuffer_data_available(&key_share_extension));

                        /* Assert that the hybrid key share is correct:
                         * IANA ID || total hybrid share size || ECC share size || ECC share || PQ share size || PQ share */
                        uint16_t sent_hybrid_iana_id;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_hybrid_iana_id));
                        EXPECT_EQUAL(sent_hybrid_iana_id, kem_pref->tls13_kem_groups[0]->iana_id);

                        uint16_t expected_hybrid_share_size =
                                S2N_SIZE_OF_KEY_SHARE_SIZE
                                + test_kem_group->curve->share_size
                                + S2N_SIZE_OF_KEY_SHARE_SIZE
                                + test_kem_group->kem->public_key_length;
                        uint16_t sent_hybrid_share_size;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_hybrid_share_size));
                        EXPECT_EQUAL(sent_hybrid_share_size, expected_hybrid_share_size);

                        uint16_t hybrid_ecc_share_size;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &hybrid_ecc_share_size));
                        EXPECT_EQUAL(hybrid_ecc_share_size, test_kem_group->curve->share_size);
                        EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, hybrid_ecc_share_size));

                        uint16_t hybrid_pq_share_size;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &hybrid_pq_share_size));
                        EXPECT_EQUAL(hybrid_pq_share_size, test_kem_group->kem->public_key_length);
                        EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, hybrid_pq_share_size));

                        /* Assert that the ECC key share is correct: IANA ID || size || share */
                        uint16_t ecc_iana_value, ecc_share_size;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &ecc_iana_value));
                        EXPECT_EQUAL(ecc_iana_value, ecc_pref->ecc_curves[0]->iana_id);
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &ecc_share_size));
                        EXPECT_EQUAL(ecc_share_size, ecc_pref->ecc_curves[0]->share_size);
                        EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, ecc_share_size));

                        /* If all the sizes/bytes were correctly written, there should be nothing left over */
                        EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                        EXPECT_SUCCESS(s2n_connection_free(conn));
                    }

                    /* Test sending key share in response to HRR */
                    {
                        struct s2n_connection *conn;
                        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                        conn->security_policy_override = &test_security_policy;
                        conn->actual_protocol_version = S2N_TLS13;

                        const struct s2n_ecc_preferences *ecc_pref = NULL;
                        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
                        EXPECT_NOT_NULL(ecc_pref);

                        const struct s2n_kem_preferences *kem_pref = NULL;
                        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
                        EXPECT_NOT_NULL(kem_pref);

                        /* This is for pre-HRR set up; force the client to generate it's default hybrid key share
                         * so that we can confirm that s2n_send_hrr_pq_hybrid_keyshare wipes it correctly. */
                        DEFER_CLEANUP(struct s2n_stuffer key_share_extension = {0}, s2n_stuffer_free);
                        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 4096));
                        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));
                        EXPECT_SUCCESS(s2n_stuffer_wipe(&key_share_extension));
                        /* Quick sanity check */
                        EXPECT_NOT_NULL(conn->secure.client_kem_group_params[0].kem_params.private_key.data);
                        EXPECT_NOT_NULL(conn->secure.client_kem_group_params[0].ecc_params.evp_pkey);

                        /* Prepare client for HRR. Client would have sent a key share for kem_pref->tls13_kem_groups[0],
                         * but server selects something else for negotiation. */
                        conn->handshake.handshake_type = HELLO_RETRY_REQUEST;
                        conn->handshake.message_number = HELLO_RETRY_MSG_NO;
                        conn->actual_protocol_version_established = 1;
                        uint8_t chosen_index = kem_pref->tls13_kem_group_count - 1;
                        EXPECT_NOT_EQUAL(chosen_index, 0);
                        const struct s2n_kem_group *negotiated_kem_group = kem_pref->tls13_kem_groups[chosen_index];
                        conn->secure.server_kem_group_params.kem_group = negotiated_kem_group;

                        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

                        /* Assert that the client saved its private keys correctly in the connection state for hybrid */
                        struct s2n_kem_group_params *kem_group_params = &conn->secure.client_kem_group_params[chosen_index];
                        EXPECT_EQUAL(kem_group_params->kem_group, negotiated_kem_group);
                        EXPECT_EQUAL(kem_group_params->kem_params.kem, negotiated_kem_group->kem);
                        EXPECT_NOT_NULL(kem_group_params->kem_params.private_key.data);
                        EXPECT_EQUAL(kem_group_params->kem_params.private_key.size,negotiated_kem_group->kem->private_key_length);
                        EXPECT_EQUAL(kem_group_params->ecc_params.negotiated_curve, negotiated_kem_group->curve);
                        EXPECT_NOT_NULL(kem_group_params->ecc_params.evp_pkey);

                        /* Assert that the client didn't generate/save any key shares that it wasn't supposed to */
                        for (size_t kem_group_index = 0;
                             kem_group_index < kem_pref->tls13_kem_group_count; kem_group_index++) {
                            if (kem_group_index == chosen_index) {
                                continue;
                            }
                            EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].kem_group);
                            EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].kem_params.kem);
                            EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].kem_params.private_key.data);
                            EXPECT_EQUAL(conn->secure.client_kem_group_params[kem_group_index].kem_params.private_key.size,0);
                            EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].ecc_params.negotiated_curve);
                            EXPECT_NULL(conn->secure.client_kem_group_params[kem_group_index].ecc_params.evp_pkey);
                        }
                        for (size_t ecc_index = 0; ecc_index < S2N_ECC_EVP_SUPPORTED_CURVES_COUNT; ecc_index++) {
                            EXPECT_NULL(conn->secure.client_ecc_evp_params[ecc_index].negotiated_curve);
                            EXPECT_NULL(conn->secure.client_ecc_evp_params[ecc_index].evp_pkey);
                        }

                        /* Assert that the client sent the correct bytes over the wire for the key share extension */
                        /* Assert total key shares extension size is correct */
                        uint16_t sent_key_shares_size;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_key_shares_size));
                        EXPECT_EQUAL(sent_key_shares_size, s2n_stuffer_data_available(&key_share_extension));

                        /* Assert that the hybrid key share is correct:
                         * IANA ID || total hybrid share size || ECC share size || ECC share || PQ share size || PQ share */
                        uint16_t sent_hybrid_iana_id;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_hybrid_iana_id));
                        EXPECT_EQUAL(sent_hybrid_iana_id, kem_pref->tls13_kem_groups[chosen_index]->iana_id);

                        uint16_t expected_hybrid_share_size =
                                S2N_SIZE_OF_KEY_SHARE_SIZE
                                + negotiated_kem_group->curve->share_size
                                + S2N_SIZE_OF_KEY_SHARE_SIZE
                                + negotiated_kem_group->kem->public_key_length;
                        uint16_t sent_hybrid_share_size;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_hybrid_share_size));
                        EXPECT_EQUAL(sent_hybrid_share_size, expected_hybrid_share_size);

                        uint16_t hybrid_ecc_share_size;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &hybrid_ecc_share_size));
                        EXPECT_EQUAL(hybrid_ecc_share_size, negotiated_kem_group->curve->share_size);
                        EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, hybrid_ecc_share_size));

                        uint16_t hybrid_pq_share_size;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &hybrid_pq_share_size));
                        EXPECT_EQUAL(hybrid_pq_share_size, negotiated_kem_group->kem->public_key_length);
                        EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, hybrid_pq_share_size));

                        /* If all the sizes/bytes were correctly written, there should be nothing left over */
                        EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                        EXPECT_SUCCESS(s2n_connection_free(conn));
                    }
                }

                /* Test failure when server chooses a KEM group that is not in the client's preferences */
                {
                    struct s2n_connection *conn;
                    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                    conn->security_policy_override = &security_policy_sike;
                    conn->actual_protocol_version = S2N_TLS13;
                    conn->handshake.handshake_type = HELLO_RETRY_REQUEST;
                    conn->handshake.message_number = HELLO_RETRY_MSG_NO;
                    conn->actual_protocol_version_established = 1;

                    conn->secure.server_kem_group_params.kem_group = &s2n_secp256r1_bike1_l1_r2;

                    DEFER_CLEANUP(struct s2n_stuffer key_share_extension = {0}, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 4096));
                    EXPECT_FAILURE_WITH_ERRNO(s2n_client_key_share_extension.send(conn, &key_share_extension), S2N_ERR_INVALID_HELLO_RETRY);

                    EXPECT_SUCCESS(s2n_connection_free(conn));
                }
            }
        }

        /* Tests for s2n_client_key_share_extension.recv */
        {
            EXPECT_SUCCESS(s2n_enable_tls13());

            /* Test that s2n_client_key_share_extension.recv ignores PQ key shares when in FIPS mode */
            if (s2n_is_in_fips_mode()) {
                struct s2n_connection *server_conn = NULL;
                EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
                server_conn->actual_protocol_version = S2N_TLS13;
                server_conn->security_policy_override = &security_policy_all;

                DEFER_CLEANUP(struct s2n_stuffer key_share_extension = { 0 }, s2n_stuffer_free);
                /* The key shares in this extension are fake - that's OK, the server should ignore the
                 * KEM group ID and skip the share. */
                EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&key_share_extension,
                        /* Shares size: 12 bytes */
                        "000C"
                        /* IANA ID for secp256r1_sikep434r2 */
                        "2F1F"
                        /* KEM group share size: 8 bytes */
                        "0008"
                        /* ECC share size: 2 bytes */
                        "0002"
                        /* Fake ECC share */
                        "FFFF"
                        /* PQ share size: 2 bytes */
                        "0002"
                        /* Fake PQ share */
                        "FFFF"
                ));

                EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

                /* .recv should have read all data */
                EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                /* Server should not have accepted any key shares */
                const struct s2n_ecc_preferences *ecc_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
                EXPECT_NOT_NULL(ecc_pref);

                for (size_t ec_index = 0; ec_index < ecc_pref->count; ec_index++) {
                    struct s2n_ecc_evp_params *received_params = &server_conn->secure.client_ecc_evp_params[ec_index];
                    EXPECT_NULL(received_params->negotiated_curve);
                    EXPECT_NULL(received_params->evp_pkey);
                }

                const struct s2n_kem_preferences *server_kem_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &server_kem_pref));
                EXPECT_NOT_NULL(server_kem_pref);

                for (size_t pq_index = 0; pq_index < server_kem_pref->tls13_kem_group_count; pq_index++) {
                    struct s2n_kem_group_params *received_params = &server_conn->secure.client_kem_group_params[pq_index];
                    EXPECT_NULL(received_params->kem_group);
                    EXPECT_NULL(received_params->ecc_params.negotiated_curve);
                    EXPECT_NULL(received_params->ecc_params.evp_pkey);
                    EXPECT_NULL(received_params->kem_params.kem);
                    EXPECT_NULL(received_params->kem_params.public_key.data);
                    EXPECT_EQUAL(received_params->kem_params.public_key.size, 0);
                    EXPECT_EQUAL(received_params->kem_params.public_key.allocated, 0);
                }

                /* Server should have indicated HRR */
                EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));

                EXPECT_SUCCESS(s2n_connection_free(server_conn));
            }

            if (!s2n_is_in_fips_mode()) {
                /* Test that s2n_client_key_share_extension.recv correctly handles the extension
                 * generated by s2n_client_key_share_extension.send */
                {
                    for (size_t i = 0; i < S2N_SUPPORTED_KEM_GROUPS_COUNT; i++) {
                        /* The PQ hybrid key share send function only sends the highest priority PQ key share. On each
                         * iteration of the outer loop of this test (index i), we populate test_kem_groups[] with a
                         * different permutation of all_kem_groups[] to ensure we handle each kem_group key share
                         * correctly. */
                        const struct s2n_kem_group *test_kem_groups[S2N_SUPPORTED_KEM_GROUPS_COUNT];
                        for (size_t j = 0; j < S2N_SUPPORTED_KEM_GROUPS_COUNT; j++) {
                            test_kem_groups[j] = all_kem_groups[(j + i) % S2N_SUPPORTED_KEM_GROUPS_COUNT];
                        }

                        const struct s2n_kem_preferences test_kem_prefs = {
                                .kem_count = 0,
                                .kems = NULL,
                                .tls13_kem_group_count = s2n_array_len(test_kem_groups),
                                .tls13_kem_groups = test_kem_groups,
                        };

                        const struct s2n_security_policy test_security_policy = {
                                .minimum_protocol_version = S2N_SSLv3,
                                .cipher_preferences = &cipher_preferences_test_all_tls13,
                                .kem_preferences = &test_kem_prefs,
                                .signature_preferences = &s2n_signature_preferences_20200207,
                                .ecc_preferences = &s2n_ecc_preferences_20200310,
                        };

                        struct s2n_connection *client_conn = NULL, *server_conn = NULL;
                        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
                        client_conn->security_policy_override = &test_security_policy;

                        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
                        server_conn->actual_protocol_version = S2N_TLS13;
                        /* Server security policy contains all the same KEM groups, but in a different order than client */
                        server_conn->security_policy_override = &security_policy_all;

                        DEFER_CLEANUP(struct s2n_stuffer key_share_extension = {0}, s2n_stuffer_free);
                        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                        EXPECT_SUCCESS(s2n_client_key_share_extension.send(client_conn, &key_share_extension));

                        /* The client writes its PQ key share directly to IO without saving it,
                         * so we make a copy from the wire to ensure that server saved it correctly. */
                        DEFER_CLEANUP(struct s2n_blob pq_key_share_copy = {0}, s2n_free);
                        EXPECT_SUCCESS(s2n_copy_pq_share(&key_share_extension, &pq_key_share_copy,
                                client_conn->secure.client_kem_group_params[0].kem_group));

                        EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

                        /* .recv should have read all data */
                        EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                        const struct s2n_ecc_preferences *ecc_pref = NULL;
                        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
                        EXPECT_NOT_NULL(ecc_pref);

                        /* Client should have sent only the first ECC key share, server should have accepted it */
                        for (size_t ec_index = 0; ec_index < ecc_pref->count; ec_index++) {
                            struct s2n_ecc_evp_params *sent_params = &client_conn->secure.client_ecc_evp_params[ec_index];
                            struct s2n_ecc_evp_params *received_params = &server_conn->secure.client_ecc_evp_params[ec_index];

                            if (ec_index == 0) {
                                EXPECT_NOT_NULL(received_params->negotiated_curve);
                                EXPECT_NOT_NULL(received_params->evp_pkey);
                                EXPECT_TRUE(s2n_public_ecc_keys_are_equal(received_params, sent_params));
                            } else {
                                EXPECT_NULL(received_params->negotiated_curve);
                                EXPECT_NULL(received_params->evp_pkey);
                            }
                        }

                        const struct s2n_kem_preferences *server_kem_pref = NULL;
                        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &server_kem_pref));
                        EXPECT_NOT_NULL(server_kem_pref);

                        /* Client should have sent only the first hybrid PQ share, server should have accepted it;
                         * the client and server KEM preferences include all the same KEM groups, but may be in
                         * different order. */
                        size_t shares_accepted_by_server = 0;
                        struct s2n_kem_group_params *sent_params = &client_conn->secure.client_kem_group_params[0];
                        for (size_t pq_index = 0; pq_index < server_kem_pref->tls13_kem_group_count; pq_index++) {
                            struct s2n_kem_group_params *received_params = &server_conn->secure.client_kem_group_params[pq_index];

                            if (sent_params->kem_group == received_params->kem_group) {
                                EXPECT_EQUAL(received_params->ecc_params.negotiated_curve,sent_params->ecc_params.negotiated_curve);
                                EXPECT_NOT_NULL(received_params->ecc_params.evp_pkey);
                                EXPECT_TRUE(s2n_public_ecc_keys_are_equal(&received_params->ecc_params, &sent_params->ecc_params));

                                EXPECT_EQUAL(received_params->kem_params.kem, test_kem_prefs.tls13_kem_groups[0]->kem);
                                EXPECT_NOT_NULL(received_params->kem_params.public_key.data);
                                EXPECT_EQUAL(received_params->kem_params.public_key.size,test_kem_prefs.tls13_kem_groups[0]->kem->public_key_length);
                                EXPECT_BYTEARRAY_EQUAL(received_params->kem_params.public_key.data,pq_key_share_copy.data,
                                        sent_params->kem_group->kem->public_key_length);

                                shares_accepted_by_server++;
                            } else {
                                EXPECT_NULL(received_params->kem_group);

                                EXPECT_NULL(received_params->ecc_params.negotiated_curve);
                                EXPECT_NULL(received_params->ecc_params.evp_pkey);

                                EXPECT_NULL(received_params->kem_params.kem);
                                EXPECT_NULL(received_params->kem_params.public_key.data);
                                EXPECT_EQUAL(received_params->kem_params.public_key.size, 0);
                                EXPECT_EQUAL(received_params->kem_params.public_key.allocated, 0);
                            }
                        }
                        EXPECT_EQUAL(shares_accepted_by_server, 1);

                        /* Server should not have indicated HRR */
                        EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

                        EXPECT_SUCCESS(s2n_connection_free(client_conn));
                        EXPECT_SUCCESS(s2n_connection_free(server_conn));
                    }
                }

                /* Test that s2n_client_key_share_extension.recv can parse multiple shares */
                {
                    struct s2n_connection *server_conn = NULL;
                    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
                    server_conn->actual_protocol_version = S2N_TLS13;
                    server_conn->security_policy_override = &security_policy_all;

                    DEFER_CLEANUP(struct s2n_stuffer key_share_extension = {0}, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                    /* Send a key share extension with shares for p256_sike, classic p256, and p256_kyber */
                    struct s2n_stuffer_reservation shares_size = {0};
                    EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &shares_size));
                    DEFER_CLEANUP(struct s2n_kem_group_params p256_sike_params = { .kem_group = &s2n_secp256r1_sike_p434_r2 }, s2n_kem_group_free);
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &p256_sike_params));
                    DEFER_CLEANUP(struct s2n_ecc_evp_params p256_params = { .negotiated_curve = &s2n_ecc_curve_secp256r1 }, s2n_ecc_evp_params_free);
                    EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&p256_params, &key_share_extension));
                    DEFER_CLEANUP(struct s2n_kem_group_params p256_kyber_params = { .kem_group = &s2n_secp256r1_kyber_512_r2 }, s2n_kem_group_free);
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &p256_kyber_params));
                    EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&shares_size));

                    EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

                    /* .recv should have read all data */
                    EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                    const struct s2n_ecc_preferences *ecc_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
                    EXPECT_NOT_NULL(ecc_pref);

                    /* Server should have accepted p256 share and no other EC shares */
                    bool p256_accepted = false;
                    for (size_t ec_index = 0; ec_index < ecc_pref->count; ec_index++) {
                        struct s2n_ecc_evp_params *received_params = &server_conn->secure.client_ecc_evp_params[ec_index];

                        if (received_params->negotiated_curve == &s2n_ecc_curve_secp256r1) {
                            EXPECT_NOT_NULL(received_params->evp_pkey);
                            p256_accepted = true;
                        } else {
                            EXPECT_NULL(received_params->negotiated_curve);
                            EXPECT_NULL(received_params->evp_pkey);
                        }
                    }
                    EXPECT_TRUE(p256_accepted);

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);

                    /* Server should have accepted p256_sike, p256_kyber, and no other hybrid shares */
                    bool p256_sike_accepted = false;
                    bool p256_kyber_accepted = false;
                    for (size_t pq_index = 0; pq_index < kem_pref->tls13_kem_group_count; pq_index++) {
                        struct s2n_kem_group_params *received_params = &server_conn->secure.client_kem_group_params[pq_index];

                        if (received_params->kem_group == &s2n_secp256r1_sike_p434_r2) {
                            EXPECT_EQUAL(received_params->kem_params.kem, &s2n_sike_p434_r2);
                            EXPECT_NOT_NULL(received_params->kem_params.public_key.data);
                            EXPECT_EQUAL(received_params->ecc_params.negotiated_curve, &s2n_ecc_curve_secp256r1);
                            EXPECT_NOT_NULL(received_params->ecc_params.evp_pkey);
                            p256_sike_accepted = true;
                        } else if (received_params->kem_group == &s2n_secp256r1_kyber_512_r2) {
                            EXPECT_EQUAL(received_params->kem_params.kem, &s2n_kyber_512_r2);
                            EXPECT_NOT_NULL(received_params->kem_params.public_key.data);
                            EXPECT_EQUAL(received_params->ecc_params.negotiated_curve, &s2n_ecc_curve_secp256r1);
                            EXPECT_NOT_NULL(received_params->ecc_params.evp_pkey);
                            p256_kyber_accepted = true;
                        } else {
                            EXPECT_NULL(received_params->kem_group);
                            EXPECT_NULL(received_params->ecc_params.negotiated_curve);
                            EXPECT_NULL(received_params->ecc_params.evp_pkey);
                            EXPECT_NULL(received_params->kem_params.kem);
                            EXPECT_NULL(received_params->kem_params.public_key.data);
                        }
                    }
                    EXPECT_TRUE(p256_sike_accepted);
                    EXPECT_TRUE(p256_kyber_accepted);

                    /* Server should not have indicated HRR */
                    EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

                    EXPECT_SUCCESS(s2n_connection_free(server_conn));
                }

                /* Test that s2n_client_key_share_extension.recv ignores an unsupported KEM Group */
                {
                    struct s2n_connection *server_conn = NULL;
                    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
                    server_conn->actual_protocol_version = S2N_TLS13;
                    /* Security policy only includes the p256_sike434r2 kem group */
                    server_conn->security_policy_override = &security_policy_sike;

                    DEFER_CLEANUP(struct s2n_stuffer key_share_extension = {0}, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                    /* Send a key share extension with shares for p256_sike, classic p256, and p256_kyber */
                    struct s2n_stuffer_reservation shares_size = {0};
                    EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &shares_size));
                    DEFER_CLEANUP(struct s2n_kem_group_params p256_sike_params = { .kem_group = &s2n_secp256r1_sike_p434_r2 }, s2n_kem_group_free);
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &p256_sike_params));
                    DEFER_CLEANUP(struct s2n_ecc_evp_params p256_params = { .negotiated_curve = &s2n_ecc_curve_secp256r1 }, s2n_ecc_evp_params_free);
                    EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&p256_params, &key_share_extension));
                    DEFER_CLEANUP(struct s2n_kem_group_params p256_kyber_params = { .kem_group = &s2n_secp256r1_kyber_512_r2 }, s2n_kem_group_free);
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &p256_kyber_params));
                    EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&shares_size));

                    EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

                    /* .recv should have read all data */
                    EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                    const struct s2n_ecc_preferences *ecc_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
                    EXPECT_NOT_NULL(ecc_pref);

                    /* Server should have accepted p256 share and no other EC shares */
                    bool p256_accepted = false;
                    for (size_t ec_index = 0; ec_index < ecc_pref->count; ec_index++) {
                        struct s2n_ecc_evp_params *received_params = &server_conn->secure.client_ecc_evp_params[ec_index];

                        if (received_params->negotiated_curve == &s2n_ecc_curve_secp256r1) {
                            EXPECT_NOT_NULL(received_params->evp_pkey);
                            p256_accepted = true;
                        } else {
                            EXPECT_NULL(received_params->negotiated_curve);
                            EXPECT_NULL(received_params->evp_pkey);
                        }
                    }
                    EXPECT_TRUE(p256_accepted);

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);

                    /* Server should have accepted p256_sike, and no other hybrid shares */
                    bool p256_sike_accepted = false;
                    for (size_t pq_index = 0; pq_index < kem_pref->tls13_kem_group_count; pq_index++) {
                        struct s2n_kem_group_params *received_params = &server_conn->secure.client_kem_group_params[pq_index];

                        if (received_params->kem_group == &s2n_secp256r1_sike_p434_r2) {
                            EXPECT_EQUAL(received_params->kem_params.kem, &s2n_sike_p434_r2);
                            EXPECT_NOT_NULL(received_params->kem_params.public_key.data);
                            EXPECT_EQUAL(received_params->ecc_params.negotiated_curve, &s2n_ecc_curve_secp256r1);
                            EXPECT_NOT_NULL(received_params->ecc_params.evp_pkey);
                            p256_sike_accepted = true;
                        } else {
                            EXPECT_NULL(received_params->kem_group);
                            EXPECT_NULL(received_params->ecc_params.negotiated_curve);
                            EXPECT_NULL(received_params->ecc_params.evp_pkey);
                            EXPECT_NULL(received_params->kem_params.kem);
                            EXPECT_NULL(received_params->kem_params.public_key.data);
                        }
                    }
                    EXPECT_TRUE(p256_sike_accepted);

                    /* Server should not have indicated HRR */
                    EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

                    EXPECT_SUCCESS(s2n_connection_free(server_conn));
                }

                /* Test that s2n_client_key_share_extension.recv ignores a KEM group with incorrect total size */
                {
                    struct s2n_connection *server_conn = NULL;
                    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
                    server_conn->actual_protocol_version = S2N_TLS13;
                    server_conn->security_policy_override = &security_policy_all;

                    DEFER_CLEANUP(struct s2n_stuffer key_share_extension = {0}, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                    /* Send a key share extension with shares for p256_sike, classic p256 */
                    struct s2n_stuffer_reservation shares_size = {0};
                    EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &shares_size));
                    EXPECT_SUCCESS(s2n_stuffer_write_uint16(&key_share_extension, TLS_PQ_KEM_GROUP_ID_SECP256R1_SIKE_P434_R2));
                    EXPECT_SUCCESS(s2n_stuffer_write_uint16(&key_share_extension, 2)); /* Wrong hybrid share size */
                    EXPECT_SUCCESS(s2n_stuffer_write_uint16(&key_share_extension, 0xFF)); /* Fake hybrid share */
                    DEFER_CLEANUP(struct s2n_ecc_evp_params p256_params = { .negotiated_curve = &s2n_ecc_curve_secp256r1 }, s2n_ecc_evp_params_free);
                    EXPECT_SUCCESS(s2n_ecdhe_parameters_send(&p256_params, &key_share_extension));
                    EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&shares_size));

                    EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

                    /* .recv should have read all data */
                    EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                    const struct s2n_ecc_preferences *ecc_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
                    EXPECT_NOT_NULL(ecc_pref);

                    /* Server should have accepted p256 share and no other EC shares */
                    bool p256_accepted = false;
                    for (size_t ec_index = 0; ec_index < ecc_pref->count; ec_index++) {
                        struct s2n_ecc_evp_params *received_params = &server_conn->secure.client_ecc_evp_params[ec_index];

                        if (received_params->negotiated_curve == &s2n_ecc_curve_secp256r1) {
                            EXPECT_NOT_NULL(received_params->evp_pkey);
                            p256_accepted = true;
                        } else {
                            EXPECT_NULL(received_params->negotiated_curve);
                            EXPECT_NULL(received_params->evp_pkey);
                        }
                    }
                    EXPECT_TRUE(p256_accepted);

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);

                    /* Server should have not have accepted any hybrid shares */
                    for (size_t pq_index = 0; pq_index < kem_pref->tls13_kem_group_count; pq_index++) {
                        struct s2n_kem_group_params *received_params = &server_conn->secure.client_kem_group_params[pq_index];

                        EXPECT_NULL(received_params->kem_group);
                        EXPECT_NULL(received_params->ecc_params.negotiated_curve);
                        EXPECT_NULL(received_params->ecc_params.evp_pkey);
                        EXPECT_NULL(received_params->kem_params.kem);
                        EXPECT_NULL(received_params->kem_params.public_key.data);
                    }

                    /* Server should not have indicated HRR */
                    EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

                    EXPECT_SUCCESS(s2n_connection_free(server_conn));
                }

                /* Test that s2n_client_key_share_extension.recv ignores a KEM group with incorrect EC share size */
                {
                    struct s2n_connection *server_conn = NULL;
                    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
                    server_conn->actual_protocol_version = S2N_TLS13;
                    server_conn->security_policy_override = &security_policy_all;

                    DEFER_CLEANUP(struct s2n_stuffer key_share_extension = {0}, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                    /* Send a key share extension with shares for p256_sike */
                    struct s2n_stuffer_reservation shares_size = {0};
                    EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &shares_size));
                    DEFER_CLEANUP(struct s2n_kem_group_params p256_sike_params = { .kem_group = &s2n_secp256r1_sike_p434_r2 }, s2n_kem_group_free);
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &p256_sike_params));
                    /* key_share_extension.blob.data[6] is the first byte of the EC share size in the overall hybrid share */
                    key_share_extension.blob.data[6] = ~key_share_extension.blob.data[6];
                    EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&shares_size));

                    EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

                    /* .recv should have read all data */
                    EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                    const struct s2n_ecc_preferences *ecc_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
                    EXPECT_NOT_NULL(ecc_pref);

                    /* Server should not have accepted any EC shares */
                    for (size_t ec_index = 0; ec_index < ecc_pref->count; ec_index++) {
                        struct s2n_ecc_evp_params *received_params = &server_conn->secure.client_ecc_evp_params[ec_index];
                        EXPECT_NULL(received_params->negotiated_curve);
                        EXPECT_NULL(received_params->evp_pkey);
                    }

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);

                    /* Server should have not have accepted any hybrid shares */
                    for (size_t pq_index = 0; pq_index < kem_pref->tls13_kem_group_count; pq_index++) {
                        struct s2n_kem_group_params *received_params = &server_conn->secure.client_kem_group_params[pq_index];
                        EXPECT_NULL(received_params->kem_group);
                        EXPECT_NULL(received_params->ecc_params.negotiated_curve);
                        EXPECT_NULL(received_params->ecc_params.evp_pkey);
                        EXPECT_NULL(received_params->kem_params.kem);
                        EXPECT_NULL(received_params->kem_params.public_key.data);
                    }

                    /* Server should have indicated HRR */
                    EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));

                    EXPECT_SUCCESS(s2n_connection_free(server_conn));
                }

                /* Test that s2n_client_key_share_extension.recv ignores a KEM group with incorrect PQ share size */
                {
                    struct s2n_connection *server_conn = NULL;
                    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
                    server_conn->actual_protocol_version = S2N_TLS13;
                    server_conn->security_policy_override = &security_policy_all;

                    DEFER_CLEANUP(struct s2n_stuffer key_share_extension = {0}, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                    /* Send a key share extension with shares for p256_sike */
                    struct s2n_stuffer_reservation shares_size = {0};
                    EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &shares_size));
                    DEFER_CLEANUP(struct s2n_kem_group_params p256_sike_params = { .kem_group = &s2n_secp256r1_sike_p434_r2 }, s2n_kem_group_free);
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &p256_sike_params));
                    /* key_share_extension.blob.data[73] is the first byte of the PQ share size in the overall hybrid share */
                    key_share_extension.blob.data[73] = ~key_share_extension.blob.data[73];
                    EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&shares_size));

                    EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

                    /* .recv should have read all data */
                    EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                    const struct s2n_ecc_preferences *ecc_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
                    EXPECT_NOT_NULL(ecc_pref);

                    /* Server should not have accepted any EC shares */
                    for (size_t ec_index = 0; ec_index < ecc_pref->count; ec_index++) {
                        struct s2n_ecc_evp_params *received_params = &server_conn->secure.client_ecc_evp_params[ec_index];
                        EXPECT_NULL(received_params->negotiated_curve);
                        EXPECT_NULL(received_params->evp_pkey);
                    }

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);

                    /* Server should have not have accepted any hybrid shares */
                    for (size_t pq_index = 0; pq_index < kem_pref->tls13_kem_group_count; pq_index++) {
                        struct s2n_kem_group_params *received_params = &server_conn->secure.client_kem_group_params[pq_index];
                        EXPECT_NULL(received_params->kem_group);
                        EXPECT_NULL(received_params->ecc_params.negotiated_curve);
                        EXPECT_NULL(received_params->ecc_params.evp_pkey);
                        EXPECT_NULL(received_params->kem_params.kem);
                        EXPECT_NULL(received_params->kem_params.public_key.data);
                    }

                    /* Server should have indicated HRR */
                    EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));

                    EXPECT_SUCCESS(s2n_connection_free(server_conn));
                }

                /* Test that s2n_client_key_share_extension.recv uses the first received key share when duplicates are present  */
                {
                    struct s2n_connection *server_conn = NULL;
                    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
                    server_conn->actual_protocol_version = S2N_TLS13;
                    server_conn->security_policy_override = &security_policy_all;

                    DEFER_CLEANUP(struct s2n_stuffer key_share_extension = {0}, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                    /* Send a key share extension with two shares for p256_sike */
                    struct s2n_stuffer_reservation shares_size = {0};
                    EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &shares_size));
                    DEFER_CLEANUP(struct s2n_kem_group_params p256_sike_params = { .kem_group = &s2n_secp256r1_sike_p434_r2 }, s2n_kem_group_free);
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &p256_sike_params));
                    DEFER_CLEANUP(struct s2n_kem_group_params p256_sike_params_extra = { .kem_group = &s2n_secp256r1_sike_p434_r2 }, s2n_kem_group_free);
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &p256_sike_params_extra));
                    EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&shares_size));

                    /* The client writes its hybrid key share directly to IO without saving it,
                     * so we make a copy of the first share from the wire to ensure that server
                     * saved the correct one. */
                    DEFER_CLEANUP(struct s2n_blob pq_key_share_copy = {0}, s2n_free);
                    EXPECT_SUCCESS(s2n_copy_pq_share(&key_share_extension, &pq_key_share_copy, &s2n_secp256r1_sike_p434_r2));

                    EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

                    /* .recv should have read all data */
                    EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                    const struct s2n_ecc_preferences *ecc_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
                    EXPECT_NOT_NULL(ecc_pref);

                    /* Server should not accepted any EC shares */
                    for (size_t ec_index = 0; ec_index < ecc_pref->count; ec_index++) {
                        struct s2n_ecc_evp_params *received_params = &server_conn->secure.client_ecc_evp_params[ec_index];
                        EXPECT_NULL(received_params->negotiated_curve);
                        EXPECT_NULL(received_params->evp_pkey);
                    }

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);

                    /* Server should have accepted the first p256_sike share */
                    bool p256_sike_accepted = false;
                    for (size_t pq_index = 0; pq_index < kem_pref->tls13_kem_group_count; pq_index++) {
                        struct s2n_kem_group_params *received_params = &server_conn->secure.client_kem_group_params[pq_index];

                        if (received_params->kem_group == &s2n_secp256r1_sike_p434_r2) {
                            EXPECT_EQUAL(received_params->kem_params.kem, &s2n_sike_p434_r2);
                            EXPECT_NOT_NULL(received_params->kem_params.public_key.data);
                            EXPECT_EQUAL(received_params->ecc_params.negotiated_curve, &s2n_ecc_curve_secp256r1);
                            EXPECT_NOT_NULL(received_params->ecc_params.evp_pkey);
                            EXPECT_BYTEARRAY_EQUAL(pq_key_share_copy.data, received_params->kem_params.public_key.data, s2n_sike_p434_r2.public_key_length);
                            p256_sike_accepted = true;
                        } else {
                            EXPECT_NULL(received_params->kem_group);
                            EXPECT_NULL(received_params->ecc_params.negotiated_curve);
                            EXPECT_NULL(received_params->ecc_params.evp_pkey);
                            EXPECT_NULL(received_params->kem_params.kem);
                            EXPECT_NULL(received_params->kem_params.public_key.data);
                        }
                    }
                    EXPECT_TRUE(p256_sike_accepted);

                    /* Server should not have indicated HRR */
                    EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

                    EXPECT_SUCCESS(s2n_connection_free(server_conn));
                }

                /* Test that s2n_client_key_share_extension.recv ignores KEM groups with EC shares that can't be parsed */
                {
                    struct s2n_connection *server_conn = NULL;
                    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
                    server_conn->actual_protocol_version = S2N_TLS13;
                    server_conn->security_policy_override = &security_policy_all;

                    DEFER_CLEANUP(struct s2n_stuffer key_share_extension = {0}, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                    /* Send a key share extension with two shares for p256_sike */
                    struct s2n_stuffer_reservation shares_size = {0};
                    EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &shares_size));
                    DEFER_CLEANUP(struct s2n_kem_group_params p256_sike_params = { .kem_group = &s2n_secp256r1_sike_p434_r2 }, s2n_kem_group_free);
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &p256_sike_params));
                    EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&shares_size));

                    /* Wipe the EC share so that the point parsing fails */
                    for (size_t i = 8; i < s2n_secp256r1_sike_p434_r2.curve->share_size; i++) {
                        key_share_extension.blob.data[i] = 0;
                    }

                    EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

                    /* .recv should have read all data */
                    EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                    const struct s2n_ecc_preferences *ecc_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
                    EXPECT_NOT_NULL(ecc_pref);

                    /* Server should not accepted any EC shares */
                    for (size_t ec_index = 0; ec_index < ecc_pref->count; ec_index++) {
                        struct s2n_ecc_evp_params *received_params = &server_conn->secure.client_ecc_evp_params[ec_index];
                        EXPECT_NULL(received_params->negotiated_curve);
                        EXPECT_NULL(received_params->evp_pkey);
                    }

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);

                    /* Server should have accepted the first p256_sike share */
                    for (size_t pq_index = 0; pq_index < kem_pref->tls13_kem_group_count; pq_index++) {
                        struct s2n_kem_group_params *received_params = &server_conn->secure.client_kem_group_params[pq_index];
                        EXPECT_NULL(received_params->kem_group);
                        EXPECT_NULL(received_params->ecc_params.negotiated_curve);
                        EXPECT_NULL(received_params->ecc_params.evp_pkey);
                        EXPECT_NULL(received_params->kem_params.kem);
                        EXPECT_NULL(received_params->kem_params.public_key.data);
                    }

                    /* Server should have indicated HRR */
                    EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));

                    EXPECT_SUCCESS(s2n_connection_free(server_conn));
                }
            }
        }
    }

    END_TEST();

    return 0;
}

/* Copies the PQ portion of the keyshare. Assumes that the read cursor of *from is
 * pointing to the beginning of the hybrid share. After copying, rewinds *from so
 * that read cursor is at the original position. */
static int s2n_copy_pq_share(struct s2n_stuffer *from, struct s2n_blob *to, const struct s2n_kem_group *kem_group) {
    notnull_check(from);
    notnull_check(to);
    notnull_check(kem_group);

    GUARD(s2n_alloc(to, kem_group->kem->public_key_length));
    /* Skip all the two-byte IDs/sizes and the ECC portion of the share */
    GUARD(s2n_stuffer_skip_read(from, 10 + kem_group->curve->share_size));
    GUARD(s2n_stuffer_read(from, to));
    GUARD(s2n_stuffer_rewind_read(from, 10 + kem_group->curve->share_size + kem_group->kem->public_key_length));

    return S2N_SUCCESS;
}

static int s2n_generate_pq_hybrid_key_share_for_test(struct s2n_stuffer *out, struct s2n_kem_group_params *kem_group_params) {
    notnull_check(out);
    notnull_check(kem_group_params);

    /* This function should never be called when in FIPS mode */
    ENSURE_POSIX(s2n_is_in_fips_mode() == false, S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);

    const struct s2n_kem_group *kem_group = kem_group_params->kem_group;
    notnull_check(kem_group);

    GUARD(s2n_stuffer_write_uint16(out, kem_group->iana_id));

    struct s2n_stuffer_reservation total_share_size = {0};
    GUARD(s2n_stuffer_reserve_uint16(out, &total_share_size));

    struct s2n_ecc_evp_params *ecc_params = &kem_group_params->ecc_params;
    ecc_params->negotiated_curve = kem_group->curve;
    GUARD(s2n_stuffer_write_uint16(out, ecc_params->negotiated_curve->share_size));
    GUARD(s2n_ecc_evp_generate_ephemeral_key(ecc_params));
    GUARD(s2n_ecc_evp_write_params_point(ecc_params, out));

    struct s2n_kem_params *kem_params = &kem_group_params->kem_params;
    kem_params->kem = kem_group->kem;
    GUARD(s2n_kem_send_public_key(out, kem_params));

    GUARD(s2n_stuffer_write_vector_size(&total_share_size));

    return S2N_SUCCESS;
}
#endif
