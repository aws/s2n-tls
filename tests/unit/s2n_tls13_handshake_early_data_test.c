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

#include "tls/s2n_handshake.h"
#include "tls/s2n_record.h"
#include "tls/s2n_tls13_handshake.h"

#include "utils/s2n_array.h"
#include "utils/s2n_mem.h"

/* Just to get access to the static functions / variables we need to test */
#include "tls/s2n_handshake_io.c"
#include "tls/s2n_tls13_handshake.c"
#include "tls/s2n_handshake_transcript.c"

#define S2N_SECRET_TYPE_COUNT 5

const uint8_t empty_secret[S2N_TLS13_SECRET_MAX_LEN] = { 0 };
message_type_t empty_handshake[S2N_MAX_HANDSHAKE_LENGTH] = { 0 };

static int s2n_check_traffic_secret_order(void* context, struct s2n_connection *conn,
                                          s2n_secret_type_t secret_type,
                                          uint8_t *secret, uint8_t secret_size)
{
    uint8_t *secrets_handled = (uint8_t *) context;
    secrets_handled[secret_type] += 1;

    switch(secret_type) {
        case S2N_CLIENT_EARLY_TRAFFIC_SECRET:
            /* For the timing: must be calculated on the ClientHello */
            /* For the digest: must be calculated on the ClientHello */
            POSIX_ENSURE_EQ(s2n_conn_get_current_message_type(conn), CLIENT_HELLO);
            /* For the extracted secret: must be calculated before all other secrets */
            POSIX_ENSURE_EQ(secrets_handled[S2N_CLIENT_HANDSHAKE_TRAFFIC_SECRET], 0);
            POSIX_ENSURE_EQ(secrets_handled[S2N_SERVER_HANDSHAKE_TRAFFIC_SECRET], 0);
            POSIX_ENSURE_EQ(secrets_handled[S2N_CLIENT_APPLICATION_TRAFFIC_SECRET], 0);
            POSIX_ENSURE_EQ(secrets_handled[S2N_SERVER_APPLICATION_TRAFFIC_SECRET], 0);
            break;
        case S2N_CLIENT_HANDSHAKE_TRAFFIC_SECRET:
            /* For the timing: must be calculated before the ClientCert or ClientFinished */
            for (uint16_t i = 0; i < conn->handshake.message_number; i++) {
                POSIX_ENSURE_NE(tls13_handshakes[conn->handshake.handshake_type][i], CLIENT_CERT);
                POSIX_ENSURE_NE(tls13_handshakes[conn->handshake.handshake_type][i], CLIENT_FINISHED);
            }
            /* For the digest: no requirements. We use a stored copy of the ServerHello digest. */
            /* For the extracted secret: must be calculated before application secrets */
            POSIX_ENSURE_EQ(secrets_handled[S2N_CLIENT_APPLICATION_TRAFFIC_SECRET], 0);
            POSIX_ENSURE_EQ(secrets_handled[S2N_SERVER_APPLICATION_TRAFFIC_SECRET], 0);
            break;
        case S2N_SERVER_HANDSHAKE_TRAFFIC_SECRET:
            /* For the timing: must be calculated before EncryptedExtensions */
            for (uint16_t i = 0; i <= conn->handshake.message_number; i++) {
                POSIX_ENSURE_NE(tls13_handshakes[conn->handshake.handshake_type][i], ENCRYPTED_EXTENSIONS);
            }
            /* For the digest: no requirements. We use a stored copy of the ServerHello digest. */
            /* For the extracted secret: must be calculated before application secrets */
            POSIX_ENSURE_EQ(secrets_handled[S2N_CLIENT_APPLICATION_TRAFFIC_SECRET], 0);
            POSIX_ENSURE_EQ(secrets_handled[S2N_SERVER_APPLICATION_TRAFFIC_SECRET], 0);
            break;
        case S2N_CLIENT_APPLICATION_TRAFFIC_SECRET:
        case S2N_SERVER_APPLICATION_TRAFFIC_SECRET:
            /* For the timing: must be calculated before ApplicationData */
            for (uint16_t i = 0; i <= conn->handshake.message_number; i++) {
                POSIX_ENSURE_NE(tls13_handshakes[conn->handshake.handshake_type][i], APPLICATION_DATA);
            }
            /* For the digest: no requirements. We use a stored copy of the ServerFinished digest. */
            /* For the extracted secret: no requirements */
            break;
    }

    return S2N_SUCCESS;
}

static S2N_RESULT s2n_setup_tls13_secrets_prereqs(struct s2n_connection *conn)
{
    conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
    RESULT_GUARD(s2n_tls13_calculate_digest(conn, conn->handshake.hashes->server_hello_digest));
    RESULT_GUARD(s2n_tls13_calculate_digest(conn, conn->handshake.hashes->server_finished_digest));

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    RESULT_ENSURE_REF(ecc_pref);

    conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
    conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
    RESULT_GUARD_POSIX(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.server_ecc_evp_params));
    RESULT_GUARD_POSIX(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

    uint8_t test_value[SHA256_DIGEST_LENGTH] = "test";
    DEFER_CLEANUP(struct s2n_psk *s2n_test_psk = s2n_external_psk_new(), s2n_psk_free);
    EXPECT_SUCCESS(s2n_psk_set_identity(s2n_test_psk, test_value, sizeof(test_value)));
    EXPECT_SUCCESS(s2n_psk_set_secret(s2n_test_psk, test_value, sizeof(test_value)));
    EXPECT_SUCCESS(s2n_alloc(&s2n_test_psk->early_secret, sizeof(test_value)));
    EXPECT_SUCCESS(s2n_psk_configure_early_data(s2n_test_psk, 1,
            s2n_tls13_aes_128_gcm_sha256.iana_value[0], s2n_tls13_aes_128_gcm_sha256.iana_value[1]));
    RESULT_GUARD_POSIX(s2n_connection_append_psk(conn, s2n_test_psk));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_key_schedule(s2n_mode mode, uint16_t handshake_type, s2n_early_data_state *early_data_transitions,
        bool *valid_test_case)
{
    RESULT_ENSURE_REF(valid_test_case);
    *valid_test_case = false;

    /* Ignore empty handshakes */
    if (memcmp(tls13_handshakes[handshake_type], empty_handshake, sizeof(empty_handshake)) == 0) {
        return S2N_RESULT_OK;
    }

    /* Ignore incomplete handshakes */
    if (!(handshake_type & NEGOTIATED)) {
        return S2N_RESULT_OK;
    }

    /* WITH_EARLY_DATA only makes sense if the early data is accepted */
    bool includes_end_of_early_data_message = (handshake_type & WITH_EARLY_DATA);
    bool requires_end_of_early_data_message = (early_data_transitions[END_OF_EARLY_DATA]);
    if (requires_end_of_early_data_message != includes_end_of_early_data_message) {
        return S2N_RESULT_OK;
    }


    uint8_t secrets_handled[S2N_SECRET_TYPE_COUNT] = { 0 };
    for (uint16_t message_number = 0; message_number < S2N_MAX_HANDSHAKE_LENGTH; message_number++) {
        struct s2n_connection *conn = s2n_connection_new(mode);
        RESULT_ENSURE_REF(conn);
        RESULT_GUARD(s2n_setup_tls13_secrets_prereqs(conn));

        /* Enable QUIC to enable the secret callbacks. This does not affect the key schedule,
         * since QUIC also uses TLS to generate early data secrets. */
        conn->quic_enabled = true;

        conn->actual_protocol_version = S2N_TLS13;
        conn->handshake.handshake_type = handshake_type;
        conn->handshake.message_number = message_number;

        if (s2n_conn_get_current_message_type(conn) == APPLICATION_DATA) {
            RESULT_GUARD_POSIX(s2n_connection_free(conn));
            break;
        }

        /* Set traffic secret validation.
         * This performs the bulk of the testing. */
        RESULT_GUARD_POSIX(s2n_connection_set_secret_callback(conn, s2n_check_traffic_secret_order, secrets_handled));

        /* Set early data state */
        conn->early_data_state = early_data_transitions[CLIENT_HELLO];
        for (size_t i = 1; i <= message_number; i++) {
            s2n_early_data_state next_state = early_data_transitions[tls13_handshakes[handshake_type][i]];
            /* Skip empty state transitions */
            if (next_state == S2N_UNKNOWN_EARLY_DATA_STATE) {
                continue;
            }
            /* Skip duplicate ClientHellos */
            if ((tls13_handshakes[handshake_type][i] == CLIENT_HELLO)) {
                continue;
            }
            RESULT_GUARD(s2n_connection_set_early_data_state(conn, next_state));
        }

        RESULT_GUARD_POSIX(s2n_tls13_handle_secrets(conn));
        RESULT_GUARD_POSIX(s2n_connection_free(conn));
    }

    RESULT_ENSURE_EQ(secrets_handled[S2N_CLIENT_HANDSHAKE_TRAFFIC_SECRET], 1);
    RESULT_ENSURE_EQ(secrets_handled[S2N_SERVER_HANDSHAKE_TRAFFIC_SECRET], 1);
    RESULT_ENSURE_EQ(secrets_handled[S2N_CLIENT_APPLICATION_TRAFFIC_SECRET], 1);
    RESULT_ENSURE_EQ(secrets_handled[S2N_SERVER_APPLICATION_TRAFFIC_SECRET], 1);

    /* The client calculates the early traffic secret if it attempts early data */
    if ((mode == S2N_CLIENT) && (early_data_transitions[CLIENT_HELLO] == S2N_EARLY_DATA_REQUESTED)) {
        RESULT_ENSURE_EQ(secrets_handled[S2N_CLIENT_EARLY_TRAFFIC_SECRET], 1);
    /* The server calculates the early traffic secret if it accepts early data */
    } else if ((mode == S2N_SERVER) && (handshake_type & WITH_EARLY_DATA)) {
        RESULT_ENSURE_EQ(secrets_handled[S2N_CLIENT_EARLY_TRAFFIC_SECRET], 1);
    } else {
        RESULT_ENSURE_EQ(secrets_handled[S2N_CLIENT_EARLY_TRAFFIC_SECRET], 0);
    }

    *valid_test_case = true;
    return S2N_RESULT_OK;
}

int main()
{
    BEGIN_TEST();

    /* Test key schedule */
    {
        bool valid_test_case = false;

        const size_t early_data_not_requested_i = 0;
        const size_t early_data_rejected_i = 1;
        const size_t early_data_accepted_i = 2;

        s2n_early_data_state client_early_data_transitions[][APPLICATION_DATA] = {
                /* early data never requested */
                { [CLIENT_HELLO] = S2N_EARLY_DATA_NOT_REQUESTED },
                /* early data rejected */
                { [CLIENT_HELLO] = S2N_EARLY_DATA_REQUESTED, [HELLO_RETRY_MSG] = S2N_EARLY_DATA_REJECTED,
                        [ENCRYPTED_EXTENSIONS] = S2N_EARLY_DATA_REJECTED },
                /* early data accepted */
                { [CLIENT_HELLO] = S2N_EARLY_DATA_REQUESTED, [HELLO_RETRY_MSG] = S2N_EARLY_DATA_REJECTED,
                        [ENCRYPTED_EXTENSIONS] = S2N_EARLY_DATA_ACCEPTED, [END_OF_EARLY_DATA] = S2N_END_OF_EARLY_DATA },
        };
        s2n_early_data_state server_early_data_transitions[][APPLICATION_DATA] = {
                /* early data never requested */
                { [CLIENT_HELLO] = S2N_EARLY_DATA_NOT_REQUESTED },
                /* early data rejected */
                { [CLIENT_HELLO] = S2N_EARLY_DATA_REJECTED },
                /* early data accepted */
                { [CLIENT_HELLO] = S2N_EARLY_DATA_ACCEPTED, [END_OF_EARLY_DATA] = S2N_END_OF_EARLY_DATA },
        };

        /* Sanity check: Test invalid cases are ignored */
        {
            /* Incomplete handshake */
            EXPECT_OK(s2n_test_key_schedule(S2N_CLIENT, 0,
                    client_early_data_transitions[early_data_accepted_i], &valid_test_case));
            EXPECT_FALSE(valid_test_case);

            /* Invalid handshake type */
            EXPECT_OK(s2n_test_key_schedule(S2N_CLIENT, NEGOTIATED | FULL_HANDSHAKE | WITH_EARLY_DATA,
                    client_early_data_transitions[early_data_accepted_i], &valid_test_case));
            EXPECT_FALSE(valid_test_case);

            /* WITH_EARLY_DATA handshake type, but early data not accepted */
            EXPECT_OK(s2n_test_key_schedule(S2N_CLIENT, NEGOTIATED | WITH_EARLY_DATA,
                    client_early_data_transitions[early_data_rejected_i], &valid_test_case));
            EXPECT_FALSE(valid_test_case);

            /* Not WITH_EARLY_DATA handshake type, but early data accepted */
            EXPECT_OK(s2n_test_key_schedule(S2N_CLIENT, NEGOTIATED,
                    client_early_data_transitions[early_data_accepted_i], &valid_test_case));
            EXPECT_FALSE(valid_test_case);
        }

        /* Test a specific known cases */
        {
            /* Early data not requested */
            EXPECT_OK(s2n_test_key_schedule(S2N_CLIENT, NEGOTIATED,
                    client_early_data_transitions[early_data_not_requested_i], &valid_test_case));
            EXPECT_TRUE(valid_test_case);
            EXPECT_OK(s2n_test_key_schedule(S2N_SERVER, NEGOTIATED,
                    server_early_data_transitions[early_data_not_requested_i], &valid_test_case));
            EXPECT_TRUE(valid_test_case);

            /* Early data rejected with HRR */
            EXPECT_OK(s2n_test_key_schedule(S2N_CLIENT, NEGOTIATED | HELLO_RETRY_REQUEST,
                    client_early_data_transitions[early_data_rejected_i], &valid_test_case));
            EXPECT_TRUE(valid_test_case);

            /* Early data rejected with extension */
            EXPECT_OK(s2n_test_key_schedule(S2N_CLIENT, NEGOTIATED,
                    client_early_data_transitions[early_data_rejected_i], &valid_test_case));
            EXPECT_TRUE(valid_test_case);
            EXPECT_OK(s2n_test_key_schedule(S2N_SERVER, NEGOTIATED,
                    server_early_data_transitions[early_data_rejected_i], &valid_test_case));
            EXPECT_TRUE(valid_test_case);

            /* Early data accepted */
            EXPECT_OK(s2n_test_key_schedule(S2N_CLIENT, NEGOTIATED | WITH_EARLY_DATA,
                    client_early_data_transitions[early_data_accepted_i], &valid_test_case));
            EXPECT_TRUE(valid_test_case);
            EXPECT_OK(s2n_test_key_schedule(S2N_SERVER, NEGOTIATED | WITH_EARLY_DATA,
                    server_early_data_transitions[early_data_accepted_i], &valid_test_case));
            EXPECT_TRUE(valid_test_case);
        }

        /* Test all client cases */
        for (size_t state_i = 0; state_i < s2n_array_len(client_early_data_transitions); state_i++) {
            for (uint16_t handshake_type = 0; handshake_type < S2N_HANDSHAKES_COUNT; handshake_type++) {
                EXPECT_OK(s2n_test_key_schedule(S2N_CLIENT, handshake_type, client_early_data_transitions[state_i],
                        &valid_test_case));
            }
        }

        /* Test all server_cases */
        for (size_t state_i = 0; state_i < s2n_array_len(server_early_data_transitions); state_i++) {
            for (uint16_t handshake_type = 0; handshake_type < S2N_HANDSHAKES_COUNT; handshake_type++) {
                EXPECT_OK(s2n_test_key_schedule(S2N_SERVER, handshake_type, server_early_data_transitions[state_i],
                        &valid_test_case));
            }
        }
    }

    /* Test early data encryption */
    {
        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-3
         *= type=test
         *# {server}  generate resumption secret "tls13 resumption":
         *#
         *#    PRK (32 octets):  7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf
         *#       da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c
         *#
         *#    hash (2 octets):  00 00
         *#
         *#    info (22 octets):  00 20 10 74 6c 73 31 33 20 72 65 73 75 6d 70 74
         *#       69 6f 6e 02 00 00
         *#
         *#    expanded (32 octets):  4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c
         *#       a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3
         */
        S2N_BLOB_FROM_HEX(psk_secret,"4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c \
                  a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3");

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-3
         *= type=test
         *# {server}  construct a NewSessionTicket handshake message:
         *#
         *#    NewSessionTicket (205 octets):  04 00 00 c9 00 00 00 1e fa d6 aa
         *#       c5 02 00 00 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 00 00
         *#       00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 ad 3c
         *#       49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11
         *#       72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 1d 28
         *#       27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37 25
         *#       a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c
         *#       5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6
         *#       17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50
         *#       5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 00 08 00 2a 00
         *#       04 00 00 04 00
         */
        /* Skip past the message type, message size, ticket lifetime,
         * ticket age add, nonce, and ticket size:
         *                                     04 00 00 c9 00 00 00 1e fa d6 aa
         *        c5 02 00 00 00 b2
         */
        S2N_BLOB_FROM_HEX(psk_identity,
                                   "2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 00 00 \
                  00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 ad 3c \
                  49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11 \
                  72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 1d 28 \
                  27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37 25 \
                  a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c \
                  5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6 \
                  17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50 \
                  5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57");
        /* Skip past the total extensions size, early data extension type,
         * and early data extension size:                         00 08 00 2a 00
         *        04
         */
        const uint32_t max_early_data = 0x00000400;

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *# {client}  send handshake record:
         *#
         *#    payload (512 octets):  01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff
         *#       93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78 76
         *#       48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00
         *#       09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12
         *#       00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00
         *#       26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34
         *#       6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b 00 2a 00
         *#       00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02
         *#       03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02
         *#       02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00
         *#       00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70
         *#       ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9
         *#       82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6
         *#       1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0
         *#       37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5
         *#       90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5
         *#       ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d
         *#       e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 fa d6 aa
         *#       cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8 8d
         *#       ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d
         */
        S2N_BLOB_FROM_HEX(client_hello_msg,
                                     "01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff \
                  93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78 76 \
                  48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00 \
                  09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 \
                  00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00 \
                  26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2 66 98 34 \
                  6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b 00 2a 00 \
                  00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 \
                  03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 \
                  02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 \
                  00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 \
                  ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 \
                  82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 \
                  1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 \
                  37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 \
                  90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 \
                  ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d \
                  e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 fa d6 aa \
                  cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca 3c f7 67 8e f5 e8 8d \
                  ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f 9d")
        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *#
         *#    complete record (517 octets):  16 03 01 02 00 01 00 01 fc 03 03 1b
         *#       c3 ce b6 bb e3 9c ff 93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49
         *#       d7 b4 bc 41 9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01 00
         *#       01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01
         *#       00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02
         *#       01 03 01 04 00 33 00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d
         *#       96 c9 9d a2 66 98 34 6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1
         *#       8d 66 8f 0b 00 2a 00 00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e
         *#       04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02
         *#       01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01
         *#       00 15 00 57 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59
         *#       ee 5f f7 af 4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb
         *#       33 fa 90 bf 1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc
         *#       55 cd 22 60 97 a3 a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3
         *#       6d 64 e8 61 be 7f d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66
         *#       4d 4e 6d a4 d2 9e e0 37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29
         *#       51 3e 3d a2 67 7f a5 90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72
         *#       14 70 f9 fb f2 97 b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6
         *#       21 a7 91 41 ef 5f 7d e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93
         *#       4a e4 d3 57 fa d6 aa cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca
         *#       3c f7 67 8e f5 e8 8d ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f
         *#       9d
         */
        S2N_BLOB_FROM_HEX(ch_record,         "16 03 01 02 00 01 00 01 fc 03 03 1b \
                  c3 ce b6 bb e3 9c ff 93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 \
                  d7 b4 bc 41 9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01 00 \
                  01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 \
                  00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 \
                  01 03 01 04 00 33 00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d \
                  96 c9 9d a2 66 98 34 6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 \
                  8d 66 8f 0b 00 2a 00 00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e \
                  04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 \
                  01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 \
                  00 15 00 57 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 \
                  ee 5f f7 af 4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb \
                  33 fa 90 bf 1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc \
                  55 cd 22 60 97 a3 a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 \
                  6d 64 e8 61 be 7f d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 \
                  4d 4e 6d a4 d2 9e e0 37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 \
                  51 3e 3d a2 67 7f a5 90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 \
                  14 70 f9 fb f2 97 b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 \
                  21 a7 91 41 ef 5f 7d e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 \
                  4a e4 d3 57 fa d6 aa cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca \
                  3c f7 67 8e f5 e8 8d ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f \
                  9d");

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *# {client}  extract secret "early":
         *#
         *#    salt:  0 (all zero octets)
         *#
         *#    IKM (32 octets):  4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c a4 c5
         *#       85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3
         *#
         *#    secret (32 octets):  9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20
         *#       bb 41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c
         */
        S2N_BLOB_FROM_HEX(early_secret,
                                   "9b 21 88 e9 b2 fc 6d 64 d7 1d c3 29 90 0e 20 \
                  bb 41 91 50 00 f6 78 aa 83 9c bb 79 7c b7 d8 33 2c");

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *# {client}  derive write traffic keys for early application data:
         *#
         *# PRK (32 octets):  3f bb e6 a6 0d eb 66 c3 0a 32 79 5a ba 0e ff 7e
         *#       aa 10 10 55 86 e7 be 5c 09 67 8d 63 b6 ca ab 62
         *#
         *# key info (13 octets):  00 10 09 74 6c 73 31 33 20 6b 65 79 00
         *#
         *# key expanded (16 octets):  92 02 05 a5 b7 bf 21 15 e6 fc 5c 29 42
         *#       83 4f 54
         *#
         *# iv info (12 octets):  00 0c 08 74 6c 73 31 33 20 69 76 00
         *#
         *# iv expanded (12 octets):  6d 47 5f 09 93 c8 e5 64 61 0d b2 b9
         */
        S2N_BLOB_FROM_HEX(iv,        "6d 47 5f 09 93 c8 e5 64 61 0d b2 b9");

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *# {client}  send application_data record:
         *#
         *#    payload (6 octets):  41 42 43 44 45 46
         */
        S2N_BLOB_FROM_HEX(payload, "41 42 43 44 45 46");
        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *#
         *#    complete record (28 octets):  17 03 03 00 17 ab 1d f4 20 e7 5c 45
         *#       7a 7c c5 d2 84 4f 76 d5 ae e4 b4 ed bf 04 9b e0
         */
        S2N_BLOB_FROM_HEX(complete_record,  "17 03 03 00 17 ab 1d f4 20 e7 5c 45 \
                  7a 7c c5 d2 84 4f 76 d5 ae e4 b4 ed bf 04 9b e0");

        /* Test client early data encryption against known client outputs */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->server_protocol_version = S2N_TLS13;

            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_pushback(&client_conn->psk_params.psk_list, (void**) &psk));
            psk->hmac_alg = S2N_HMAC_SHA256;
            EXPECT_SUCCESS(s2n_psk_configure_early_data(psk, max_early_data, 0x13, 0x01));

            /* Rewrite early secret with known early secret. */
            EXPECT_SUCCESS(s2n_dup(&early_secret, &psk->early_secret));

            /* Rewrite hashes with known ClientHello */
            EXPECT_SUCCESS(s2n_hash_update(&client_conn->handshake.hashes->sha256,
                    client_hello_msg.data, client_hello_msg.size));

            client_conn->handshake.message_number = 0;
            client_conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_SUCCESS(s2n_tls13_handle_secrets(client_conn));

            /* Check early secret secret set correctly */
            EXPECT_BYTEARRAY_EQUAL(client_conn->secrets.tls12.rsa_premaster_secret, early_secret.data, early_secret.size);

            /* Check IV calculated correctly */
            EXPECT_BYTEARRAY_EQUAL(client_conn->secure.client_implicit_iv, iv.data, iv.size);

            /* Check payload encrypted correctly */
            EXPECT_SUCCESS(s2n_record_write(client_conn, TLS_APPLICATION_DATA, &payload));
            EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->out), complete_record.size);
            EXPECT_BYTEARRAY_EQUAL(client_conn->out.blob.data, complete_record.data, complete_record.size);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        }

/* The known ClientHello uses the x25519 curve,
 * which the S2N server won't accept if the EVP APIs are not supported */
#if EVP_APIS_SUPPORTED
        /* Test server early data encryption with known client inputs */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(server_conn, max_early_data));

            DEFER_CLEANUP(struct s2n_psk *psk = s2n_external_psk_new(), s2n_psk_free);
            psk->type = S2N_PSK_TYPE_RESUMPTION;
            EXPECT_SUCCESS(s2n_psk_set_identity(psk, psk_identity.data, psk_identity.size));
            EXPECT_SUCCESS(s2n_psk_set_secret(psk, psk_secret.data, psk_secret.size));
            EXPECT_SUCCESS(s2n_psk_configure_early_data(psk, max_early_data, 0x13, 0x01));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, psk));
            /* We need to explicitly set the psk_params type to skip our stateless session resumption recv 
             * code because the handshake traces we're using are meant for stateful session resumption.
             * TODO: https://github.com/aws/s2n-tls/issues/2742 */
            server_conn->psk_params.type = S2N_PSK_TYPE_EXTERNAL;

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));

            EXPECT_SUCCESS(s2n_stuffer_write(&input, &ch_record));

            s2n_blocked_status blocked = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), END_OF_EARLY_DATA);
            EXPECT_EQUAL(s2n_stuffer_data_available(&input), 0);

            EXPECT_SUCCESS(s2n_stuffer_write(&input, &complete_record));

            DEFER_CLEANUP(struct s2n_blob actual_payload = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&actual_payload, payload.size));
            int r = s2n_recv(server_conn, actual_payload.data, actual_payload.size, &blocked);
            EXPECT_EQUAL(r, payload.size);
            EXPECT_BYTEARRAY_EQUAL(actual_payload.data, payload.data, payload.size);
            EXPECT_EQUAL(s2n_stuffer_data_available(&input), 0);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
#endif
    }

    END_TEST();
}
