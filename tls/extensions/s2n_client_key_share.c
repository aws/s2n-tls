/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/extensions/s2n_client_key_share.h"

#include "crypto/s2n_ecc.h"
#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

#define S2N_SIZE_OF_EXTENSION_TYPE          2
#define S2N_SIZE_OF_EXTENSION_DATA_SIZE     2
#define S2N_SIZE_OF_CLIENT_SHARES_SIZE      2
#define S2N_SIZE_OF_NAMED_GROUP             2
#define S2N_SIZE_OF_KEY_SHARE_SIZE          2

/**
 * Specified in https://tools.ietf.org/html/rfc8446#section-4.2.8
 * "The "key_share" extension contains the endpoint's cryptographic parameters."
 *
 * Structure:
 * Extension type (2 bytes)
 * Extension data size (2 bytes)
 * Client shares size (2 bytes)
 * Client shares:
 *      Named group (2 bytes)
 *      Key share size (2 bytes)
 *      Key share (variable size)
 **/

static int s2n_ecdhe_parameters_send(struct s2n_connection *conn, struct s2n_stuffer *out);

int s2n_client_key_share_extension_size;

int s2n_client_key_share_init()
{
    s2n_client_key_share_extension_size = S2N_SIZE_OF_EXTENSION_TYPE
            + S2N_SIZE_OF_EXTENSION_DATA_SIZE
            + S2N_SIZE_OF_CLIENT_SHARES_SIZE;

    for (int i = 0; i < S2N_ECC_SUPPORTED_CURVES_COUNT; i++) {
        s2n_client_key_share_extension_size += S2N_SIZE_OF_KEY_SHARE_SIZE + S2N_SIZE_OF_NAMED_GROUP;
        s2n_client_key_share_extension_size += s2n_ecc_supported_curves[i].share_size;
    }

    return 0;
}

int s2n_extensions_client_key_share_recv(struct s2n_connection *conn, struct s2n_stuffer *extension)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}

int s2n_extensions_client_key_share_size(struct s2n_connection *conn)
{
    return s2n_client_key_share_extension_size;
}

int s2n_extensions_client_key_share_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    const uint16_t extension_type = TLS_EXTENSION_KEY_SHARE;
    const uint16_t extension_data_size =
            s2n_client_key_share_extension_size - S2N_SIZE_OF_EXTENSION_TYPE - S2N_SIZE_OF_EXTENSION_DATA_SIZE;
    const uint16_t client_shares_size =
            extension_data_size - S2N_SIZE_OF_CLIENT_SHARES_SIZE;

    GUARD(s2n_stuffer_write_uint16(out, extension_type));
    GUARD(s2n_stuffer_write_uint16(out, extension_data_size));
    GUARD(s2n_stuffer_write_uint16(out, client_shares_size));

    GUARD(s2n_ecdhe_parameters_send(conn, out));

    return 0;
}

static int s2n_ecdhe_parameters_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    const struct s2n_ecc_named_curve *named_curve = NULL;
    struct s2n_ecc_params *ecc_params = NULL;

    for (int i = 0; i < S2N_ECC_SUPPORTED_CURVES_COUNT; i++) {
        ecc_params = &conn->secure.client_ecc_params[i];
        named_curve = &s2n_ecc_supported_curves[i];

        ecc_params->negotiated_curve = named_curve;

        GUARD(s2n_stuffer_write_uint16(out, named_curve->iana_id));
        GUARD(s2n_stuffer_write_uint16(out, named_curve->share_size));

        GUARD(s2n_ecc_generate_ephemeral_key(ecc_params));
        GUARD(s2n_ecc_write_ecc_params_point(ecc_params, out));
    }

    return 0;
}
