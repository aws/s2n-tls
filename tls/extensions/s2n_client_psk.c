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

#include <sys/param.h>
#include <stdint.h>

#include "crypto/s2n_hash.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls_parameters.h"

#include "utils/s2n_safety.h"

#define SIZE_OF_BINDER_SIZE sizeof(uint8_t)
#define SIZE_OF_BINDER_LIST_SIZE sizeof(uint16_t)

static bool s2n_client_psk_should_send(struct s2n_connection *conn);
static int s2n_client_psk_send(struct s2n_connection *conn, struct s2n_stuffer *out);
static int s2n_client_psk_recv(struct s2n_connection *conn, struct s2n_stuffer *extension);

const s2n_extension_type s2n_client_psk_extension = {
    .iana_value = TLS_EXTENSION_PRE_SHARED_KEY,
    .is_response = false,
    .send = s2n_client_psk_send,
    .recv = s2n_client_psk_recv,
    .should_send = s2n_client_psk_should_send,
    .if_missing = s2n_extension_noop_if_missing,
};

static bool s2n_client_psk_should_send(struct s2n_connection *conn)
{
    return conn && s2n_connection_get_protocol_version(conn) >= S2N_TLS13
            && conn->psk_params.psk_list.len;
}

static int s2n_client_psk_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    notnull_check(conn);

    struct s2n_psk_parameters *psk_params = &conn->psk_params;
    struct s2n_array *psk_list = &psk_params->psk_list;

    struct s2n_stuffer_reservation identity_list_size;
    GUARD(s2n_stuffer_reserve_uint16(out, &identity_list_size));

    uint16_t binder_list_size = SIZE_OF_BINDER_LIST_SIZE;

    for (size_t i = 0; i < psk_list->len; i++) {
        struct s2n_psk *psk;
        GUARD_AS_POSIX(s2n_array_get(psk_list, i, (void**) &psk));
        notnull_check(psk);

        /* Write the identity */
        GUARD(s2n_stuffer_write_uint16(out, psk->identity.size));
        GUARD(s2n_stuffer_write(out, &psk->identity));
        GUARD(s2n_stuffer_write_uint32(out, psk->obfuscated_ticket_age));

        /* Calculate binder size */
        uint8_t hash_size;
        GUARD(s2n_hash_digest_size(psk->hash_alg, &hash_size));
        binder_list_size += hash_size + SIZE_OF_BINDER_SIZE;
    }

    GUARD(s2n_stuffer_write_vector_size(&identity_list_size));

    /* Calculating the binders requires a complete ClientHello, and at this point
     * the extension size, extension list size, and message size are all blank.
     *
     * We'll write placeholder data to ensure the extension and extension list sizes
     * are calculated correctly, then rewrite the binders with real data later. */
    psk_params->binder_list_size = binder_list_size;
    GUARD(s2n_stuffer_skip_write(out, binder_list_size));

    return S2N_SUCCESS;
}

static S2N_RESULT s2n_match_psk_identity(struct s2n_array *known_psks, const struct s2n_blob *wire_identity,
        struct s2n_psk **match)
{
    ENSURE_REF(match);
    ENSURE_REF(wire_identity);
    ENSURE_REF(known_psks);

    *match = NULL;

    for(size_t i = 0; i < known_psks->len; i++) {
        struct s2n_psk *psk;
        GUARD_RESULT(s2n_array_get(known_psks, i, (void**)&psk));
        ENSURE_REF(psk);

        if (wire_identity->size != psk->identity.size) {
            continue;
        }

        if (memcmp(psk->identity.data, wire_identity->data, wire_identity->size) == 0) {
            *match = psk;
            return S2N_RESULT_OK;
        }
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_client_psk_recv_identity_list(struct s2n_connection *conn, struct s2n_stuffer *wire_identities_in)
{
    ENSURE_REF(conn);

    uint8_t wire_index = 0;
    while(s2n_stuffer_data_available(wire_identities_in)) {
        uint16_t identity_size;
        GUARD_AS_RESULT(s2n_stuffer_read_uint16(wire_identities_in, &identity_size));

        uint8_t *identity_data;
        ENSURE_REF(identity_data = s2n_stuffer_raw_read(wire_identities_in, identity_size));

        struct s2n_blob identity;
        GUARD_AS_RESULT(s2n_blob_init(&identity, identity_data, identity_size));

        /* TODO: Validate obfuscated_ticket_age when using session tickets.
         *
         * "For identities established externally, an obfuscated_ticket_age of 0 SHOULD be
         * used, and servers MUST ignore the value."
         */
        uint32_t obfuscated_ticket_age;
        GUARD_AS_RESULT(s2n_stuffer_read_uint32(wire_identities_in, &obfuscated_ticket_age));

        /* TODO: Implement the callback to choose a PSK.
         *
         * When we don't have a callback configured to choose a PSK, we should fall back to accepting
         * the first PSK identity that also exists in our list of supported PSKs. */
        GUARD_RESULT(s2n_match_psk_identity(&conn->psk_params.psk_list, &identity, &conn->psk_params.chosen_psk));

        if (conn->psk_params.chosen_psk) {
            conn->psk_params.chosen_psk_wire_index = wire_index;
            return S2N_RESULT_OK;
        }

        wire_index++;
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_client_psk_recv_binder_list(struct s2n_connection *conn, struct s2n_blob *partial_client_hello,
        struct s2n_stuffer *wire_binders_in)
{
    ENSURE_REF(conn);

    uint8_t wire_index = 0;
    while(s2n_stuffer_data_available(wire_binders_in)) {
        uint8_t wire_binder_size;
        GUARD_AS_RESULT(s2n_stuffer_read_uint8(wire_binders_in, &wire_binder_size));

        uint8_t *wire_binder_data;
        ENSURE_REF(wire_binder_data = s2n_stuffer_raw_read(wire_binders_in, wire_binder_size));

        struct s2n_blob wire_binder;
        GUARD_AS_RESULT(s2n_blob_init(&wire_binder, wire_binder_data, wire_binder_size));

        if (wire_index == conn->psk_params.chosen_psk_wire_index) {
            GUARD_AS_RESULT(s2n_psk_verify_binder(conn, conn->psk_params.chosen_psk,
                    partial_client_hello, &wire_binder));
            return S2N_RESULT_OK;
        }
        wire_index++;
    }
    BAIL(S2N_ERR_BAD_MESSAGE);
}

static S2N_RESULT s2n_client_psk_recv_identities(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    ENSURE_REF(conn);

    uint16_t identity_list_size;
    GUARD_AS_RESULT(s2n_stuffer_read_uint16(extension, &identity_list_size));

    uint8_t *identity_list_data;
    ENSURE_REF(identity_list_data = s2n_stuffer_raw_read(extension, identity_list_size));

    struct s2n_blob identity_list_blob;
    GUARD_AS_RESULT(s2n_blob_init(&identity_list_blob, identity_list_data, identity_list_size));

    struct s2n_stuffer identity_list;
    GUARD_AS_RESULT(s2n_stuffer_init(&identity_list, &identity_list_blob));
    GUARD_AS_RESULT(s2n_stuffer_skip_write(&identity_list, identity_list_blob.size));

    return s2n_client_psk_recv_identity_list(conn, &identity_list);
}

static S2N_RESULT s2n_client_psk_recv_binders(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    uint16_t binder_list_size;
    GUARD_AS_RESULT(s2n_stuffer_read_uint16(extension, &binder_list_size));

    uint8_t *binder_list_data;
    ENSURE_REF(binder_list_data = s2n_stuffer_raw_read(extension, binder_list_size));

    struct s2n_blob binder_list_blob;
    GUARD_AS_RESULT(s2n_blob_init(&binder_list_blob, binder_list_data, binder_list_size));

    struct s2n_stuffer binder_list;
    GUARD_AS_RESULT(s2n_stuffer_init(&binder_list, &binder_list_blob));
    GUARD_AS_RESULT(s2n_stuffer_skip_write(&binder_list, binder_list_blob.size));

    /* Record the ClientHello message up to but not including the binder list.
     * This is required to calculate the binder for the chosen PSK. */
    struct s2n_blob partial_client_hello = { 0 };
    const struct s2n_stuffer *client_hello = &conn->handshake.io;
    uint16_t partial_client_hello_size = client_hello->write_cursor
            - binder_list_blob.size - SIZE_OF_BINDER_LIST_SIZE;
    GUARD_AS_RESULT(s2n_blob_slice(&client_hello->blob, &partial_client_hello, 0, partial_client_hello_size));

    return s2n_client_psk_recv_binder_list(conn, &partial_client_hello, &binder_list);
}

int s2n_client_psk_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    notnull_check(conn);

    if (s2n_connection_get_protocol_version(conn) < S2N_TLS13) {
        return S2N_SUCCESS;
    }

    if (s2n_result_is_error(s2n_client_psk_recv_identities(conn, extension))) {
        /* https://tools.ietf.org/html/rfc8446#section-4.2.11:
         *   "If no acceptable PSKs are found, the server SHOULD perform a non-PSK
         *   handshake if possible."
         */
        conn->psk_params.chosen_psk = NULL;
    }

    if (conn->psk_params.chosen_psk) {
        /* https://tools.ietf.org/html/rfc8446#section-4.2.11:
         *   "Prior to accepting PSK key establishment, the server MUST validate
         *   the corresponding binder value. If this value is not present or does
         *   not validate, the server MUST abort the handshake."
         */
        GUARD_AS_POSIX(s2n_client_psk_recv_binders(conn, extension));
    }

    /* At this point, we have either chosen a PSK or fallen back to a full handshake.
     * Wipe any PSKs not chosen. */
    GUARD_AS_POSIX(s2n_psk_parameters_free_unused_psks(&conn->psk_params));

    return S2N_SUCCESS;
}
