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

#include "tls/s2n_connection_serialize.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_tls13_key_schedule.h"

int s2n_connection_serialization_length(struct s2n_connection *conn, uint32_t *length)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->config);
    POSIX_ENSURE_REF(conn->secure);
    POSIX_ENSURE_REF(conn->secure->cipher_suite);
    POSIX_ENSURE_REF(length);

    POSIX_ENSURE(conn->config->serialized_connection_version != S2N_SERIALIZED_CONN_NONE,
            S2N_ERR_INVALID_STATE);

    if (conn->actual_protocol_version >= S2N_TLS13) {
        uint8_t secret_size = 0;
        POSIX_GUARD(s2n_hmac_digest_size(conn->secure->cipher_suite->prf_alg, &secret_size));
        *length = S2N_SERIALIZED_CONN_FIXED_SIZE + (secret_size * 3);
    } else {
        *length = S2N_SERIALIZED_CONN_TLS12_SIZE;
    }

    return S2N_SUCCESS;
}

static S2N_RESULT s2n_connection_serialize_tls13_secrets(struct s2n_connection *conn, struct s2n_stuffer *output)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->secure);
    RESULT_ENSURE_REF(conn->secure->cipher_suite);

    uint8_t secret_size = 0;
    RESULT_GUARD_POSIX(s2n_hmac_digest_size(conn->secure->cipher_suite->prf_alg, &secret_size));

    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(output, conn->secrets.version.tls13.client_app_secret,
            secret_size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(output, conn->secrets.version.tls13.server_app_secret,
            secret_size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(output, conn->secrets.version.tls13.resumption_master_secret,
            secret_size));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_connection_serialize_secrets(struct s2n_connection *conn, struct s2n_stuffer *output)
{
    RESULT_ENSURE_REF(conn);

    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(output, conn->secrets.version.tls12.master_secret,
            S2N_TLS_SECRET_LEN));
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(output, conn->handshake_params.client_random,
            S2N_TLS_RANDOM_DATA_LEN));
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(output, conn->handshake_params.server_random,
            S2N_TLS_RANDOM_DATA_LEN));
    return S2N_RESULT_OK;
}

int s2n_connection_serialize(struct s2n_connection *conn, uint8_t *buffer, uint32_t buffer_length)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure);
    POSIX_ENSURE_REF(conn->secure->cipher_suite);
    POSIX_ENSURE_REF(conn->config);
    POSIX_ENSURE_REF(buffer);

    POSIX_ENSURE(conn->config->serialized_connection_version != S2N_SERIALIZED_CONN_NONE,
            S2N_ERR_INVALID_STATE);

    /* This method must be called after negotiation */
    POSIX_ENSURE(s2n_handshake_is_complete(conn), S2N_ERR_HANDSHAKE_NOT_COMPLETE);

    /* Best effort check for pending input or output data.
     * This method should not be called until the application has stopped sending and receiving.
     * Saving partial read or partial write state would complicate this problem.
     */
    POSIX_ENSURE(s2n_stuffer_data_available(&conn->header_in) == 0, S2N_ERR_INVALID_STATE);
    POSIX_ENSURE(s2n_stuffer_data_available(&conn->in) == 0, S2N_ERR_INVALID_STATE);
    POSIX_ENSURE(s2n_stuffer_data_available(&conn->out) == 0, S2N_ERR_INVALID_STATE);

    uint32_t context_length = 0;
    POSIX_GUARD(s2n_connection_serialization_length(conn, &context_length));
    POSIX_ENSURE(buffer_length >= context_length, S2N_ERR_INSUFFICIENT_MEM_SIZE);

    struct s2n_blob context_blob = { 0 };
    POSIX_GUARD(s2n_blob_init(&context_blob, buffer, buffer_length));
    struct s2n_stuffer output = { 0 };
    POSIX_GUARD(s2n_stuffer_init(&output, &context_blob));

    POSIX_GUARD(s2n_stuffer_write_uint64(&output, S2N_SERIALIZED_CONN_V1));

    POSIX_GUARD(s2n_stuffer_write_uint8(&output, conn->actual_protocol_version / 10));
    POSIX_GUARD(s2n_stuffer_write_uint8(&output, conn->actual_protocol_version % 10));
    POSIX_GUARD(s2n_stuffer_write_bytes(&output, conn->secure->cipher_suite->iana_value, S2N_TLS_CIPHER_SUITE_LEN));

    POSIX_GUARD(s2n_stuffer_write_bytes(&output, conn->secure->client_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
    POSIX_GUARD(s2n_stuffer_write_bytes(&output, conn->secure->server_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));

    POSIX_GUARD(s2n_stuffer_write_uint16(&output, conn->max_outgoing_fragment_length));

    if (conn->actual_protocol_version >= S2N_TLS13) {
        POSIX_GUARD_RESULT(s2n_connection_serialize_tls13_secrets(conn, &output));
    } else {
        POSIX_GUARD_RESULT(s2n_connection_serialize_secrets(conn, &output));
    }

    return S2N_SUCCESS;
}

struct s2n_connection_deserialize {
    uint8_t protocol_version;
    struct s2n_cipher_suite *cipher_suite;
    uint8_t client_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN];
    uint8_t server_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN];
    uint16_t max_fragment_len;
    union {
        struct {
            uint8_t master_secret[S2N_TLS_SECRET_LEN];
            uint8_t client_random[S2N_TLS_RANDOM_DATA_LEN];
            uint8_t server_random[S2N_TLS_RANDOM_DATA_LEN];
        } tls12;
        struct {
            uint8_t secret_size;
            uint8_t client_application_secret[S2N_TLS_SECRET_LEN];
            uint8_t server_application_secret[S2N_TLS_SECRET_LEN];
            uint8_t resumption_master_secret[S2N_TLS_SECRET_LEN];
        } tls13;
    } version;
};

static S2N_RESULT s2n_connection_deserialize_tls13_secrets(struct s2n_stuffer *input,
        struct s2n_connection_deserialize *parsed_values)
{
    RESULT_ENSURE_REF(input);
    RESULT_ENSURE_REF(parsed_values);

    RESULT_GUARD_POSIX(s2n_hmac_digest_size(parsed_values->cipher_suite->prf_alg,
            &parsed_values->version.tls13.secret_size));
    RESULT_GUARD_POSIX(s2n_stuffer_read_bytes(input, parsed_values->version.tls13.client_application_secret,
            parsed_values->version.tls13.secret_size));
    RESULT_GUARD_POSIX(s2n_stuffer_read_bytes(input, parsed_values->version.tls13.server_application_secret,
            parsed_values->version.tls13.secret_size));
    RESULT_GUARD_POSIX(s2n_stuffer_read_bytes(input, parsed_values->version.tls13.resumption_master_secret,
            parsed_values->version.tls13.secret_size));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_connection_deserialize_secrets(struct s2n_stuffer *input,
        struct s2n_connection_deserialize *parsed_values)
{
    RESULT_ENSURE_REF(input);
    RESULT_ENSURE_REF(parsed_values);

    RESULT_GUARD_POSIX(s2n_stuffer_read_bytes(input, parsed_values->version.tls12.master_secret, S2N_TLS_SECRET_LEN));
    RESULT_GUARD_POSIX(s2n_stuffer_read_bytes(input, parsed_values->version.tls12.client_random, S2N_TLS_RANDOM_DATA_LEN));
    RESULT_GUARD_POSIX(s2n_stuffer_read_bytes(input, parsed_values->version.tls12.server_random, S2N_TLS_RANDOM_DATA_LEN));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_connection_deserialize_parse(uint8_t *buffer, uint32_t buffer_length,
        struct s2n_connection_deserialize *parsed_values)
{
    RESULT_ENSURE_REF(parsed_values);

    struct s2n_blob context_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&context_blob, buffer, buffer_length));
    struct s2n_stuffer input = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&input, &context_blob));

    uint64_t serialized_version = 0;
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint64(&input, &serialized_version));
    /* No other version is supported currently */
    RESULT_ENSURE_EQ(serialized_version, S2N_SERIALIZED_CONN_V1);

    uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN] = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_read_bytes(&input, protocol_version, S2N_TLS_PROTOCOL_VERSION_LEN));
    parsed_values->protocol_version = (protocol_version[0] * 10) + protocol_version[1];

    uint8_t cipher_suite[S2N_TLS_CIPHER_SUITE_LEN] = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_read_bytes(&input, cipher_suite, S2N_TLS_CIPHER_SUITE_LEN));
    RESULT_GUARD(s2n_cipher_suite_from_iana(cipher_suite, S2N_TLS_CIPHER_SUITE_LEN, &parsed_values->cipher_suite));

    RESULT_GUARD_POSIX(s2n_stuffer_read_bytes(&input, parsed_values->client_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
    RESULT_GUARD_POSIX(s2n_stuffer_read_bytes(&input, parsed_values->server_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));

    RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&input, &parsed_values->max_fragment_len));

    if (parsed_values->protocol_version >= S2N_TLS13) {
        RESULT_GUARD(s2n_connection_deserialize_tls13_secrets(&input, parsed_values));
    } else {
        RESULT_GUARD(s2n_connection_deserialize_secrets(&input, parsed_values));
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_restore_tls13_secrets(struct s2n_connection *conn, struct s2n_connection_deserialize *parsed_values)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(parsed_values);

    RESULT_CHECKED_MEMCPY(conn->secrets.version.tls13.client_app_secret,
            parsed_values->version.tls13.client_application_secret, parsed_values->version.tls13.secret_size);
    RESULT_CHECKED_MEMCPY(conn->secrets.version.tls13.server_app_secret,
            parsed_values->version.tls13.server_application_secret, parsed_values->version.tls13.secret_size);
    RESULT_CHECKED_MEMCPY(conn->secrets.version.tls13.resumption_master_secret,
            parsed_values->version.tls13.resumption_master_secret, parsed_values->version.tls13.secret_size);

    RESULT_GUARD(s2n_tls13_key_schedule_set_key(conn, S2N_MASTER_SECRET, S2N_SERVER));
    RESULT_GUARD(s2n_tls13_key_schedule_set_key(conn, S2N_MASTER_SECRET, S2N_CLIENT));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_restore_secrets(struct s2n_connection *conn, struct s2n_connection_deserialize *parsed_values)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(parsed_values);

    RESULT_CHECKED_MEMCPY(conn->secrets.version.tls12.master_secret, parsed_values->version.tls12.master_secret,
            S2N_TLS_SECRET_LEN);
    RESULT_CHECKED_MEMCPY(conn->handshake_params.client_random, parsed_values->version.tls12.client_random,
            S2N_TLS_RANDOM_DATA_LEN);
    RESULT_CHECKED_MEMCPY(conn->handshake_params.server_random, parsed_values->version.tls12.server_random,
            S2N_TLS_RANDOM_DATA_LEN);
    RESULT_GUARD_POSIX(s2n_prf_key_expansion(conn));

    return S2N_RESULT_OK;
}

int s2n_connection_deserialize(struct s2n_connection *conn, uint8_t *buffer, uint32_t buffer_length)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure);
    POSIX_ENSURE_REF(buffer);

    /* Read parsed values into a temporary struct so that the connection is unaltered if parsing fails */
    struct s2n_connection_deserialize parsed_values = { 0 };
    POSIX_ENSURE(s2n_result_is_ok(s2n_connection_deserialize_parse(buffer, buffer_length, &parsed_values)),
            S2N_INVALID_SERIALIZED_CONNECTION);

    /* Rehydrate fields now that parsing has completed successfully */
    conn->actual_protocol_version = parsed_values.protocol_version;
    conn->secure->cipher_suite = parsed_values.cipher_suite;
    POSIX_GUARD_RESULT(s2n_connection_set_max_fragment_length(conn, parsed_values.max_fragment_len));

    /* Mark the connection as having been deserialized */
    conn->deserialized_conn = true;

    /* Key expansion */
    if (parsed_values.protocol_version >= S2N_TLS13) {
        POSIX_GUARD_RESULT(s2n_restore_tls13_secrets(conn, &parsed_values));
    } else {
        POSIX_GUARD_RESULT(s2n_restore_secrets(conn, &parsed_values));
    }

    /* Wait until after key generation to restore sequence numbers since they get zeroed during
     * key expansion */
    POSIX_CHECKED_MEMCPY(conn->secure->client_sequence_number, parsed_values.client_sequence_number,
            S2N_TLS_SEQUENCE_NUM_LEN);
    POSIX_CHECKED_MEMCPY(conn->secure->server_sequence_number, parsed_values.server_sequence_number,
            S2N_TLS_SEQUENCE_NUM_LEN);

    conn->client = conn->secure;
    conn->server = conn->secure;

    return S2N_SUCCESS;
}
