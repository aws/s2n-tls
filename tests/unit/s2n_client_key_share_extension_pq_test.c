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

#include "s2n_test.h"

/* clang-format off */
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls13.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/extensions/s2n_key_share.h"
#include "tls/s2n_security_policies.h"

#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"
#include "pq-crypto/s2n_pq.h"
/* clang-format on */

#define HELLO_RETRY_MSG_NO 1
#define MEM_FOR_EXTENSION  4096

static int s2n_generate_pq_hybrid_key_share_for_test(struct s2n_stuffer *out, struct s2n_kem_group_params *kem_group_params);
static int s2n_copy_pq_share(struct s2n_stuffer *from, struct s2n_blob *to, const struct s2n_kem_group *kem_group, bool len_prefixed);

int main()
{
    BEGIN_TEST();
    /* PQ hybrid tests for s2n_client_key_share_extension */
    for (int len_prefixed = 0; len_prefixed < 2; len_prefixed++) {
        int draft_revision = (len_prefixed) ? 0 : 5;
        const struct s2n_kem_preferences kem_prefs_all = {
            .kem_count = 0,
            .kems = NULL,
            .tls13_kem_group_count = S2N_SUPPORTED_KEM_GROUPS_COUNT,
            .tls13_kem_groups = ALL_SUPPORTED_KEM_GROUPS,
            .tls13_pq_hybrid_draft_revision = draft_revision
        };

        const struct s2n_security_policy security_policy_all = {
            .minimum_protocol_version = S2N_SSLv3,
            .cipher_preferences = &cipher_preferences_test_all_tls13,
            .kem_preferences = &kem_prefs_all,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .ecc_preferences = &s2n_ecc_preferences_20200310,
        };

        /* Tests for s2n_client_key_share_extension.send */
        {
            /* Test that s2n_client_key_share_extension.send sends only ECC key shares
             * when PQ is disabled, even if tls13_kem_groups is non-null. */
            if (!s2n_pq_is_enabled()) {
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

                DEFER_CLEANUP(struct s2n_stuffer key_share_extension = { 0 }, s2n_stuffer_free);
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
             * and ECC shares correctly when PQ is enabled. */
            if (s2n_pq_is_enabled()) {
                for (size_t i = 0; i < S2N_SUPPORTED_KEM_GROUPS_COUNT; i++) {
                    /* The PQ hybrid key share send function only sends the highest priority PQ key share. On each
                     * iteration of the outer loop of this test (index i), we populate test_kem_groups[] with a
                     * different permutation of all_kem_groups[] to ensure we handle each kem_group key share
                     * correctly. */
                    const struct s2n_kem_group *test_kem_groups[S2N_SUPPORTED_KEM_GROUPS_COUNT];
                    for (size_t j = 0; j < S2N_SUPPORTED_KEM_GROUPS_COUNT; j++) {
                        /* cppcheck-suppress moduloofone */
                        test_kem_groups[j] = ALL_SUPPORTED_KEM_GROUPS[(j + i) % S2N_SUPPORTED_KEM_GROUPS_COUNT];
                    }

                    const struct s2n_kem_preferences test_kem_prefs = {
                        .kem_count = 0,
                        .kems = NULL,
                        .tls13_kem_group_count = s2n_array_len(test_kem_groups),
                        .tls13_kem_groups = test_kem_groups,
                        .tls13_pq_hybrid_draft_revision = draft_revision
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

                        DEFER_CLEANUP(struct s2n_stuffer key_share_extension = { 0 }, s2n_stuffer_free);
                        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, MEM_FOR_EXTENSION));
                        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

                        /* Assert that the client saved its private keys correctly in the connection state
                         * for both hybrid PQ and classic ECC */
                        struct s2n_kem_group_params *kem_group_params = &conn->kex_params.client_kem_group_params;
                        EXPECT_EQUAL(kem_group_params->kem_group, test_kem_group);
                        EXPECT_EQUAL(kem_group_params->kem_params.kem, test_kem_group->kem);
                        EXPECT_NOT_NULL(kem_group_params->kem_params.private_key.data);
                        EXPECT_EQUAL(kem_group_params->kem_params.private_key.size, test_kem_group->kem->private_key_length);
                        EXPECT_EQUAL(kem_group_params->ecc_params.negotiated_curve, test_kem_group->curve);
                        EXPECT_NOT_NULL(kem_group_params->ecc_params.evp_pkey);

                        struct s2n_ecc_evp_params *ecc_params = &conn->kex_params.client_ecc_evp_params;
                        EXPECT_EQUAL(ecc_params->negotiated_curve, ecc_pref->ecc_curves[0]);
                        EXPECT_NOT_NULL(ecc_params->evp_pkey);

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

                        uint16_t expected_hybrid_share_size = 0;

                        if (len_prefixed) {
                            expected_hybrid_share_size = S2N_SIZE_OF_KEY_SHARE_SIZE
                                    + test_kem_group->curve->share_size
                                    + S2N_SIZE_OF_KEY_SHARE_SIZE
                                    + test_kem_group->kem->public_key_length;
                        } else {
                            expected_hybrid_share_size = test_kem_group->curve->share_size + test_kem_group->kem->public_key_length;
                        }

                        uint16_t sent_hybrid_share_size = 0;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_hybrid_share_size));
                        EXPECT_EQUAL(sent_hybrid_share_size, expected_hybrid_share_size);

                        if (len_prefixed) {
                            uint16_t hybrid_ecc_share_size = 0;
                            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &hybrid_ecc_share_size));
                            EXPECT_EQUAL(hybrid_ecc_share_size, test_kem_group->curve->share_size);
                        }
                        EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, test_kem_group->curve->share_size));

                        if (len_prefixed) {
                            uint16_t hybrid_pq_share_size = 0;
                            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &hybrid_pq_share_size));
                            EXPECT_EQUAL(hybrid_pq_share_size, test_kem_group->kem->public_key_length);
                        }
                        EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, test_kem_group->kem->public_key_length));

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
                    /* Need at least two KEM's to test ClientHelloRetry fallback */
                    if (test_security_policy.kem_preferences->tls13_kem_group_count >= 2) {
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

                        /* This is for pre-HRR set up: force the client to generate its default hybrid key share. */
                        DEFER_CLEANUP(struct s2n_stuffer key_share_extension = { 0 }, s2n_stuffer_free);
                        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, MEM_FOR_EXTENSION));
                        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));
                        EXPECT_SUCCESS(s2n_stuffer_wipe(&key_share_extension));
                        /* Quick sanity check */
                        EXPECT_NOT_NULL(conn->kex_params.client_kem_group_params.kem_params.private_key.data);
                        EXPECT_NOT_NULL(conn->kex_params.client_kem_group_params.ecc_params.evp_pkey);

                        /* Prepare client for HRR. Client would have sent a key share for kem_pref->tls13_kem_groups[0],
                         * but server selects something else for negotiation. */
                        conn->handshake.handshake_type = HELLO_RETRY_REQUEST;
                        conn->handshake.message_number = HELLO_RETRY_MSG_NO;
                        conn->actual_protocol_version_established = 1;
                        uint8_t chosen_index = kem_pref->tls13_kem_group_count - 1;
                        EXPECT_NOT_EQUAL(chosen_index, 0);
                        const struct s2n_kem_group *negotiated_kem_group = kem_pref->tls13_kem_groups[chosen_index];
                        conn->kex_params.server_kem_group_params.kem_group = negotiated_kem_group;

                        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

                        /* Assert that the client saved its private keys correctly in the connection state for hybrid */
                        struct s2n_kem_group_params *kem_group_params = &conn->kex_params.client_kem_group_params;
                        EXPECT_EQUAL(kem_group_params->kem_group, negotiated_kem_group);
                        EXPECT_EQUAL(kem_group_params->kem_params.kem, negotiated_kem_group->kem);
                        EXPECT_NOT_NULL(kem_group_params->kem_params.private_key.data);
                        EXPECT_EQUAL(kem_group_params->kem_params.private_key.size, negotiated_kem_group->kem->private_key_length);
                        EXPECT_EQUAL(kem_group_params->ecc_params.negotiated_curve, negotiated_kem_group->curve);
                        EXPECT_NOT_NULL(kem_group_params->ecc_params.evp_pkey);

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

                        uint16_t expected_hybrid_share_size;

                        if (len_prefixed) {
                            expected_hybrid_share_size = S2N_SIZE_OF_KEY_SHARE_SIZE
                                    + negotiated_kem_group->curve->share_size
                                    + S2N_SIZE_OF_KEY_SHARE_SIZE
                                    + negotiated_kem_group->kem->public_key_length;
                        } else {
                            expected_hybrid_share_size = negotiated_kem_group->curve->share_size + negotiated_kem_group->kem->public_key_length;
                        }

                        uint16_t sent_hybrid_share_size;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &sent_hybrid_share_size));
                        EXPECT_EQUAL(sent_hybrid_share_size, expected_hybrid_share_size);

                        if (len_prefixed) {
                            uint16_t hybrid_ecc_share_size;
                            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &hybrid_ecc_share_size));
                            EXPECT_EQUAL(hybrid_ecc_share_size, negotiated_kem_group->curve->share_size);
                        }
                        EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, negotiated_kem_group->curve->share_size));

                        if (len_prefixed) {
                            uint16_t hybrid_pq_share_size;
                            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &hybrid_pq_share_size));
                            EXPECT_EQUAL(hybrid_pq_share_size, negotiated_kem_group->kem->public_key_length);
                        }
                        EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, negotiated_kem_group->kem->public_key_length));

                        /* If all the sizes/bytes were correctly written, there should be nothing left over */
                        EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                        EXPECT_SUCCESS(s2n_connection_free(conn));
                    }

                    /* Test sending in response to HRR for early data */
                    {
                        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
                        conn->security_policy_override = &test_security_policy;
                        EXPECT_NOT_NULL(conn);

                        const struct s2n_ecc_preferences *ecc_preferences = NULL;
                        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
                        EXPECT_NOT_NULL(ecc_preferences);

                        const struct s2n_kem_preferences *kem_pref = NULL;
                        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(conn, &kem_pref));
                        EXPECT_NOT_NULL(kem_pref);

                        struct s2n_stuffer first_extension = { 0 }, second_extension = { 0 };
                        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&first_extension, MEM_FOR_EXTENSION));
                        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&second_extension, MEM_FOR_EXTENSION));

                        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &first_extension));

                        conn->kex_params.server_kem_group_params.kem_group = conn->kex_params.client_kem_group_params.kem_group;
                        conn->kex_params.server_kem_group_params.ecc_params.negotiated_curve =
                                conn->kex_params.client_kem_group_params.ecc_params.negotiated_curve;

                        /* Setup the client to have received a HelloRetryRequest */
                        EXPECT_MEMCPY_SUCCESS(conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
                        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
                        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(conn));
                        conn->early_data_state = S2N_EARLY_DATA_REJECTED;

                        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &second_extension));

                        /* Read the total length of both extensions.
                         * The first keys extension contains multiple shares, so should be longer than the second. */
                        uint16_t first_sent_key_shares_size = 0, second_sent_key_shares_size = 0;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&first_extension, &first_sent_key_shares_size));
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&second_extension, &second_sent_key_shares_size));
                        EXPECT_EQUAL(first_sent_key_shares_size, s2n_stuffer_data_available(&first_extension));
                        EXPECT_EQUAL(second_sent_key_shares_size, s2n_stuffer_data_available(&second_extension));
                        EXPECT_TRUE(second_sent_key_shares_size < first_sent_key_shares_size);

                        /* Read the iana of the first share.
                         * Both shares should contain the same iana, and it should be equal to the server's chosen kem group. */
                        uint16_t first_sent_hybrid_iana_id = 0, second_sent_hybrid_iana_id = 0;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&first_extension, &first_sent_hybrid_iana_id));
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&second_extension, &second_sent_hybrid_iana_id));
                        EXPECT_EQUAL(first_sent_hybrid_iana_id, conn->kex_params.server_kem_group_params.kem_group->iana_id);
                        EXPECT_EQUAL(first_sent_hybrid_iana_id, second_sent_hybrid_iana_id);

                        /* Read the total share size, including both ecc and kem.
                         * The first extension contains multiple shares, so should contain more data than the share size.
                         * The second extension only contains one share, so should contain only the share size. */
                        uint16_t first_total_hybrid_share_size = 0, second_total_hybrid_share_size = 0;
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&first_extension, &first_total_hybrid_share_size));
                        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&second_extension, &second_total_hybrid_share_size));
                        EXPECT_TRUE(first_total_hybrid_share_size < s2n_stuffer_data_available(&first_extension));
                        EXPECT_EQUAL(second_total_hybrid_share_size, s2n_stuffer_data_available(&second_extension));

                        if (len_prefixed) {
                            /* Read the ecc share size.
                             * The ecc share should be identical for both, so the size should be the same. */
                            uint16_t first_ecc_share_size = 0, second_ecc_share_size = 0;
                            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&first_extension, &first_ecc_share_size));
                            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&second_extension, &second_ecc_share_size));
                            EXPECT_EQUAL(first_ecc_share_size, second_ecc_share_size);
                        }

                        /* Read the ecc share.
                         * The ecc share should be identical for both. */
                        struct s2n_kem_group_params *kem_group_params = &conn->kex_params.client_kem_group_params;
                        int ecc_share_size = kem_group_params->ecc_params.negotiated_curve->share_size;
                        uint8_t *first_ecc_share_data = NULL, *second_ecc_share_data = NULL;
                        EXPECT_NOT_NULL(first_ecc_share_data = s2n_stuffer_raw_read(&first_extension, ecc_share_size));
                        EXPECT_NOT_NULL(second_ecc_share_data = s2n_stuffer_raw_read(&second_extension, ecc_share_size));
                        EXPECT_BYTEARRAY_EQUAL(first_ecc_share_data, second_ecc_share_data, ecc_share_size);

                        if (len_prefixed) {
                            /* The pq share should take up the rest of the key share.
                             * For now the pq share is different between extensions, so we can't assert anything else. */
                            uint16_t second_pq_share_size = 0;
                            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&second_extension, &second_pq_share_size));
                            EXPECT_EQUAL(second_pq_share_size, s2n_stuffer_data_available(&second_extension));
                        }

                        EXPECT_SUCCESS(s2n_stuffer_free(&first_extension));
                        EXPECT_SUCCESS(s2n_stuffer_free(&second_extension));
                        EXPECT_SUCCESS(s2n_connection_free(conn));
                    }
                }
            }
        }

        /* Tests for s2n_client_key_share_extension.recv */
        {
            EXPECT_SUCCESS(s2n_enable_tls13_in_test());

            /* Test that s2n_client_key_share_extension.recv ignores PQ key shares when PQ is disabled */
            if (!s2n_pq_is_enabled()) {
                struct s2n_connection *server_conn = NULL;
                EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
                server_conn->actual_protocol_version = S2N_TLS13;
                server_conn->security_policy_override = &security_policy_all;
                EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

                DEFER_CLEANUP(struct s2n_stuffer key_share_extension = { 0 }, s2n_stuffer_free);
                /* The key shares in this extension are fake - that's OK, the server should ignore the
                 * KEM group ID and skip the share. */
                EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&key_share_extension,
                        /* Shares size: 12 bytes */
                        "000C"
                        /* IANA ID for secp256r1_sikep434r3 */
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
                        "FFFF"));

                EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

                /* .recv should have read all data */
                EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                /* Server should not have accepted any key shares */
                const struct s2n_ecc_preferences *ecc_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
                EXPECT_NOT_NULL(ecc_pref);

                struct s2n_ecc_evp_params *received_ecc_params = &server_conn->kex_params.client_ecc_evp_params;
                EXPECT_NULL(received_ecc_params->negotiated_curve);
                EXPECT_NULL(received_ecc_params->evp_pkey);

                const struct s2n_kem_preferences *server_kem_pref = NULL;
                EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &server_kem_pref));
                EXPECT_NOT_NULL(server_kem_pref);

                struct s2n_kem_group_params *received_pq_params = &server_conn->kex_params.client_kem_group_params;
                EXPECT_NULL(received_pq_params->kem_group);
                EXPECT_NULL(received_pq_params->ecc_params.negotiated_curve);
                EXPECT_NULL(received_pq_params->ecc_params.evp_pkey);
                EXPECT_NULL(received_pq_params->kem_params.kem);
                EXPECT_NULL(received_pq_params->kem_params.public_key.data);
                EXPECT_EQUAL(received_pq_params->kem_params.public_key.size, 0);
                EXPECT_EQUAL(received_pq_params->kem_params.public_key.allocated, 0);

                /* Server should have indicated HRR */
                EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));

                EXPECT_SUCCESS(s2n_connection_free(server_conn));
            }

            if (s2n_pq_is_enabled()) {
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
                            /* cppcheck-suppress moduloofone */
                            test_kem_groups[j] = ALL_SUPPORTED_KEM_GROUPS[(j + i) % S2N_SUPPORTED_KEM_GROUPS_COUNT];
                        }

                        const struct s2n_kem_preferences test_kem_prefs = {
                            .kem_count = 0,
                            .kems = NULL,
                            .tls13_kem_group_count = s2n_array_len(test_kem_groups),
                            .tls13_kem_groups = test_kem_groups,
                            .tls13_pq_hybrid_draft_revision = draft_revision
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
                        EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

                        DEFER_CLEANUP(struct s2n_stuffer key_share_extension = { 0 }, s2n_stuffer_free);
                        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                        EXPECT_SUCCESS(s2n_client_key_share_extension.send(client_conn, &key_share_extension));

                        /* The client writes its PQ key share directly to IO without saving it,
                         * so we make a copy from the wire to ensure that server saved it correctly. */
                        DEFER_CLEANUP(struct s2n_blob pq_key_share_copy = { 0 }, s2n_free);
                        EXPECT_SUCCESS(s2n_copy_pq_share(&key_share_extension, &pq_key_share_copy,
                                client_conn->kex_params.client_kem_group_params.kem_group, len_prefixed));

                        EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));

                        /* .recv should have read all data */
                        EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                        const struct s2n_ecc_preferences *ecc_pref = NULL;
                        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
                        EXPECT_NOT_NULL(ecc_pref);

                        /* Client should have sent only the first ECC key share, server should have accepted it */
                        struct s2n_ecc_evp_params *sent_ecc_params = &client_conn->kex_params.client_ecc_evp_params;
                        struct s2n_ecc_evp_params *received_ecc_params = &server_conn->kex_params.client_ecc_evp_params;
                        EXPECT_NOT_NULL(received_ecc_params->negotiated_curve);
                        EXPECT_NOT_NULL(received_ecc_params->evp_pkey);
                        EXPECT_TRUE(s2n_public_ecc_keys_are_equal(received_ecc_params, sent_ecc_params));

                        const struct s2n_kem_preferences *server_kem_pref = NULL;
                        EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &server_kem_pref));
                        EXPECT_NOT_NULL(server_kem_pref);

                        /* Client should have sent only the first hybrid PQ share, server should have accepted it;
                         * the client and server KEM preferences include all the same KEM groups, but may be in
                         * different order. */
                        struct s2n_kem_group_params *sent_pq_params = &client_conn->kex_params.client_kem_group_params;
                        struct s2n_kem_group_params *received_pq_params = &server_conn->kex_params.client_kem_group_params;

                        EXPECT_EQUAL(received_pq_params->ecc_params.negotiated_curve, sent_pq_params->ecc_params.negotiated_curve);
                        EXPECT_NOT_NULL(received_pq_params->ecc_params.evp_pkey);
                        EXPECT_TRUE(s2n_public_ecc_keys_are_equal(&received_pq_params->ecc_params, &sent_pq_params->ecc_params));

                        EXPECT_EQUAL(received_pq_params->kem_params.kem, test_kem_prefs.tls13_kem_groups[0]->kem);
                        EXPECT_NOT_NULL(received_pq_params->kem_params.public_key.data);
                        EXPECT_EQUAL(received_pq_params->kem_params.public_key.size, test_kem_prefs.tls13_kem_groups[0]->kem->public_key_length);
                        EXPECT_BYTEARRAY_EQUAL(received_pq_params->kem_params.public_key.data, pq_key_share_copy.data,
                                sent_pq_params->kem_group->kem->public_key_length);

                        /* Server should not have indicated HRR */
                        EXPECT_FALSE(s2n_is_hello_retry_handshake(server_conn));

                        EXPECT_SUCCESS(s2n_connection_free(client_conn));
                        EXPECT_SUCCESS(s2n_connection_free(server_conn));
                    }
                }

                /* Test that s2n_client_key_share_extension.recv selects the highest priority share,
                 * even if it appears last in the client's list of shares. */
                /* Need at least two KEM's to test fallback */
                if (security_policy_all.kem_preferences->tls13_kem_group_count >= 2) {
                    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
                    EXPECT_NOT_NULL(server_conn);
                    server_conn->actual_protocol_version = S2N_TLS13;
                    server_conn->security_policy_override = &security_policy_all;
                    EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);
                    EXPECT_TRUE(kem_pref->tls13_kem_group_count >= 2);

                    struct s2n_kem_group_params client_pq_params[] = {
                        { .kem_group = kem_pref->tls13_kem_groups[0], .kem_params = { .len_prefixed = len_prefixed } },
                        { .kem_group = kem_pref->tls13_kem_groups[1], .kem_params = { .len_prefixed = len_prefixed } }
                    };

                    struct s2n_stuffer key_share_extension = { 0 };
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                    struct s2n_stuffer_reservation keyshare_list_size = { 0 };
                    EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &keyshare_list_size));
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &client_pq_params[1]));
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &client_pq_params[0]));
                    EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&keyshare_list_size));

                    EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
                    EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                    /* Does not trigger retries */
                    EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

                    /* Highest priority group (0) share present */
                    struct s2n_kem_group_params *server_params = &server_conn->kex_params.client_kem_group_params;
                    EXPECT_EQUAL(server_params->kem_group, kem_pref->tls13_kem_groups[0]);
                    EXPECT_NOT_NULL(server_params->kem_params.public_key.data);
                    EXPECT_NOT_NULL(server_params->ecc_params.evp_pkey);

                    for (size_t i = 0; i < s2n_array_len(client_pq_params); i++) {
                        EXPECT_SUCCESS(s2n_kem_group_free(&client_pq_params[i]));
                    }
                    EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
                    EXPECT_SUCCESS(s2n_connection_free(server_conn));
                }

                /* Test that s2n_client_key_share_extension.recv ignores shares for groups not offered
                 * by the client / "mutually supported", and triggers a retry instead.
                 */
                /* Need at least two KEM's to test fallback */
                if (security_policy_all.kem_preferences->tls13_kem_group_count >= 2) {
                    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
                    EXPECT_NOT_NULL(server_conn);
                    server_conn->actual_protocol_version = S2N_TLS13;
                    server_conn->security_policy_override = &security_policy_all;

                    /* Do NOT mark group 0 as mutually supported */
                    EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));
                    server_conn->kex_params.mutually_supported_kem_groups[0] = NULL;

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);
                    EXPECT_TRUE(kem_pref->tls13_kem_group_count >= 2);

                    struct s2n_kem_group_params client_pq_params = { .kem_group = kem_pref->tls13_kem_groups[0],
                        .kem_params = { .len_prefixed = len_prefixed } };

                    struct s2n_stuffer key_share_extension = { 0 };
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                    struct s2n_stuffer_reservation keyshare_list_size = { 0 };
                    EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &keyshare_list_size));
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &client_pq_params));
                    EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&keyshare_list_size));

                    EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
                    EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                    /* Client key share ignored, so retry triggered */
                    EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

                    /* No valid client key share present */
                    struct s2n_kem_group_params *server_params = &server_conn->kex_params.client_kem_group_params;
                    EXPECT_NULL(server_params->kem_group);
                    EXPECT_NULL(server_params->kem_params.public_key.data);
                    EXPECT_NULL(server_params->ecc_params.evp_pkey);

                    EXPECT_SUCCESS(s2n_kem_group_free(&client_pq_params));
                    EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
                    EXPECT_SUCCESS(s2n_connection_free(server_conn));
                }

                /* Test that s2n_client_key_share_extension.recv ignores shares for curves not offered
                 * by the client / "mutually supported", and chooses a lower priority curve instead.
                 */
                /* Need at least two KEM's to test fallback */
                if (security_policy_all.kem_preferences->tls13_kem_group_count >= 2) {
                    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
                    EXPECT_NOT_NULL(server_conn);
                    server_conn->actual_protocol_version = S2N_TLS13;
                    server_conn->security_policy_override = &security_policy_all;

                    /* Do NOT mark curve 0 as mutually supported */
                    EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));
                    server_conn->kex_params.mutually_supported_kem_groups[0] = NULL;

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);
                    EXPECT_TRUE(kem_pref->tls13_kem_group_count >= 2);

                    struct s2n_kem_group_params client_pq_params[] = {
                        { .kem_group = kem_pref->tls13_kem_groups[0], .kem_params = { .len_prefixed = len_prefixed } },
                        { .kem_group = kem_pref->tls13_kem_groups[1], .kem_params = { .len_prefixed = len_prefixed } }
                    };

                    struct s2n_stuffer key_share_extension = { 0 };
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                    struct s2n_stuffer_reservation keyshare_list_size = { 0 };
                    EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &keyshare_list_size));
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &client_pq_params[0]));
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &client_pq_params[1]));
                    EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&keyshare_list_size));

                    EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
                    EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                    /* Does not trigger a retry */
                    EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

                    /* Second highest priority group (1) share present, because highest priority not "mutually supported" */
                    struct s2n_kem_group_params *server_params = &server_conn->kex_params.client_kem_group_params;
                    EXPECT_EQUAL(server_params->kem_group, kem_pref->tls13_kem_groups[1]);
                    EXPECT_NOT_NULL(server_params->kem_params.public_key.data);
                    EXPECT_NOT_NULL(server_params->ecc_params.evp_pkey);

                    for (size_t i = 0; i < s2n_array_len(client_pq_params); i++) {
                        EXPECT_SUCCESS(s2n_kem_group_free(&client_pq_params[i]));
                    }
                    EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
                    EXPECT_SUCCESS(s2n_connection_free(server_conn));
                }

                /* Test that s2n_client_key_share_extension.recv ignores shares that can't be parsed,
                 * and continues to parse valid shares afterwards. */
                /* Need at least two KEM's to test fallback */
                if (security_policy_all.kem_preferences->tls13_kem_group_count >= 2) {
                    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
                    EXPECT_NOT_NULL(server_conn);
                    server_conn->security_policy_override = &security_policy_all;
                    EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
                    EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

                    struct s2n_stuffer key_share_extension = { 0 };
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);
                    EXPECT_TRUE(kem_pref->tls13_kem_group_count >= 2);

                    struct s2n_kem_group_params client_pq_params[] = {
                        { .kem_group = kem_pref->tls13_kem_groups[0], .kem_params = { .len_prefixed = len_prefixed } },
                        { .kem_group = kem_pref->tls13_kem_groups[1], .kem_params = { .len_prefixed = len_prefixed } }
                    };

                    /* Write share list length */
                    struct s2n_stuffer_reservation keyshare_list_size = { 0 };
                    EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &keyshare_list_size));
                    /* Write first share. Mess up point by erasing most of it */
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &client_pq_params[0]));
                    const struct s2n_kem_group *kem_group = kem_pref->tls13_kem_groups[0];
                    size_t hybrid_share_size = kem_group->curve->share_size + kem_group->kem->public_key_length;

                    if (len_prefixed) {
                        hybrid_share_size += (2 * S2N_SIZE_OF_KEY_SHARE_SIZE);
                    }

                    EXPECT_SUCCESS(s2n_stuffer_wipe_n(&key_share_extension, hybrid_share_size));
                    EXPECT_SUCCESS(s2n_stuffer_skip_write(&key_share_extension, hybrid_share_size));
                    /* Write second, valid share */
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &client_pq_params[1]));
                    /* Finish share list length */
                    EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&keyshare_list_size));

                    EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
                    EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                    /* Should have chosen curve 1, because curve 0 was malformed */
                    struct s2n_kem_group_params *server_params = &server_conn->kex_params.client_kem_group_params;
                    EXPECT_EQUAL(server_params->kem_group, kem_pref->tls13_kem_groups[1]);
                    EXPECT_NOT_NULL(server_params->kem_params.public_key.data);
                    EXPECT_NOT_NULL(server_params->ecc_params.evp_pkey);

                    for (size_t i = 0; i < s2n_array_len(client_pq_params); i++) {
                        EXPECT_SUCCESS(s2n_kem_group_free(&client_pq_params[i]));
                    }
                    EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
                    EXPECT_SUCCESS(s2n_connection_free(server_conn));
                }

                /* Test that s2n_client_key_share_extension.recv ignores shares that can't be parsed,
                 * and doesn't ignore / forget / overwrite valid shares already parsed. */
                /* Need at least two KEM's to test fallback */
                if (security_policy_all.kem_preferences->tls13_kem_group_count >= 2) {
                    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
                    EXPECT_NOT_NULL(server_conn);
                    server_conn->security_policy_override = &security_policy_all;
                    EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
                    EXPECT_OK(s2n_set_all_mutually_supported_groups(server_conn));

                    struct s2n_stuffer key_share_extension = { 0 };
                    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 8192));

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    EXPECT_SUCCESS(s2n_connection_get_kem_preferences(server_conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);
                    EXPECT_TRUE(kem_pref->tls13_kem_group_count >= 2);

                    struct s2n_kem_group_params client_pq_params[] = {
                        { .kem_group = kem_pref->tls13_kem_groups[0], .kem_params = { .len_prefixed = len_prefixed } },
                        { .kem_group = kem_pref->tls13_kem_groups[1], .kem_params = { .len_prefixed = len_prefixed } }
                    };

                    /* Write share list length */
                    struct s2n_stuffer_reservation keyshare_list_size = { 0 };
                    EXPECT_SUCCESS(s2n_stuffer_reserve_uint16(&key_share_extension, &keyshare_list_size));
                    /* Write first, valid share */
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &client_pq_params[0]));
                    /* Write second share. Mess up point by erasing most of it */
                    EXPECT_SUCCESS(s2n_generate_pq_hybrid_key_share_for_test(&key_share_extension, &client_pq_params[1]));
                    const struct s2n_kem_group *kem_group = kem_pref->tls13_kem_groups[0];
                    size_t hybrid_share_size = kem_group->curve->share_size + kem_group->kem->public_key_length;

                    if (len_prefixed) {
                        hybrid_share_size += (2 * S2N_SIZE_OF_KEY_SHARE_SIZE);
                    }

                    EXPECT_SUCCESS(s2n_stuffer_wipe_n(&key_share_extension, hybrid_share_size / 2));
                    EXPECT_SUCCESS(s2n_stuffer_skip_write(&key_share_extension, hybrid_share_size / 2));
                    /* Finish share list length */
                    EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&keyshare_list_size));

                    EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
                    EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

                    /* Should have chosen highest priority key share (0) */
                    struct s2n_kem_group_params *server_params = &server_conn->kex_params.client_kem_group_params;
                    EXPECT_EQUAL(server_params->kem_group, kem_pref->tls13_kem_groups[0]);
                    EXPECT_NOT_NULL(server_params->kem_params.public_key.data);
                    EXPECT_NOT_NULL(server_params->ecc_params.evp_pkey);

                    for (size_t i = 0; i < s2n_array_len(client_pq_params); i++) {
                        EXPECT_SUCCESS(s2n_kem_group_free(&client_pq_params[i]));
                    }
                    EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
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
static int s2n_copy_pq_share(struct s2n_stuffer *from, struct s2n_blob *to, const struct s2n_kem_group *kem_group, bool len_prefixed)
{
    POSIX_ENSURE_REF(from);
    POSIX_ENSURE_REF(to);
    POSIX_ENSURE_REF(kem_group);

    int keyshare_extension_offset = 10;

    if (!len_prefixed) {
        keyshare_extension_offset -= (2 * S2N_SIZE_OF_KEY_SHARE_SIZE);
    }

    POSIX_GUARD(s2n_alloc(to, kem_group->kem->public_key_length));
    /* Skip all the two-byte IDs/sizes and the ECC portion of the share */
    POSIX_GUARD(s2n_stuffer_skip_read(from, keyshare_extension_offset + kem_group->curve->share_size));
    POSIX_GUARD(s2n_stuffer_read(from, to));
    POSIX_GUARD(s2n_stuffer_rewind_read(from, keyshare_extension_offset + kem_group->curve->share_size + kem_group->kem->public_key_length));

    return S2N_SUCCESS;
}

static int s2n_generate_pq_hybrid_key_share_for_test(struct s2n_stuffer *out, struct s2n_kem_group_params *kem_group_params)
{
    POSIX_ENSURE_REF(out);
    POSIX_ENSURE_REF(kem_group_params);

    /* This function should never be called when PQ is disabled */
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

    const struct s2n_kem_group *kem_group = kem_group_params->kem_group;
    POSIX_ENSURE_REF(kem_group);

    POSIX_GUARD(s2n_stuffer_write_uint16(out, kem_group->iana_id));

    struct s2n_stuffer_reservation total_share_size = { 0 };
    POSIX_GUARD(s2n_stuffer_reserve_uint16(out, &total_share_size));

    struct s2n_ecc_evp_params *ecc_params = &kem_group_params->ecc_params;
    ecc_params->negotiated_curve = kem_group->curve;
    struct s2n_kem_params *kem_params = &kem_group_params->kem_params;

    if (kem_params->len_prefixed) {
        POSIX_GUARD(s2n_stuffer_write_uint16(out, ecc_params->negotiated_curve->share_size));
    }
    POSIX_GUARD(s2n_ecc_evp_generate_ephemeral_key(ecc_params));
    POSIX_GUARD(s2n_ecc_evp_write_params_point(ecc_params, out));

    kem_params->kem = kem_group->kem;
    POSIX_GUARD(s2n_kem_send_public_key(out, kem_params));

    POSIX_GUARD(s2n_stuffer_write_vector_size(&total_share_size));

    return S2N_SUCCESS;
}
