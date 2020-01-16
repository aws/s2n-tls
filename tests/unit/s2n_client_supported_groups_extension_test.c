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

#include "s2n_test.h"

#include <stdint.h>

#include "tls/s2n_alerts.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_client_extensions.h"
#include "tls/s2n_tls.h"
#include "tls/extensions/s2n_client_key_share.h"
#include "tls/extensions/s2n_key_share.h"

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

int main()
{
    BEGIN_TEST();

    {
        /* Test that unknown TLS_EXTENSION_SUPPORTED_GROUPS values are ignored */
        struct s2n_ecc_named_curve unsupported_curves[2] = {
                { .iana_id = 0x0, .libcrypto_nid = 0, .name = 0x0, .share_size = 0 },
                { .iana_id = 0xFF01, .libcrypto_nid = 0, .name = 0x0, .share_size = 0 },
        };
        int ec_curves_count = s2n_array_len(unsupported_curves);
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        struct s2n_stuffer supported_groups_extension;
        EXPECT_SUCCESS(s2n_stuffer_alloc(&supported_groups_extension, 2 + ec_curves_count * 2));
        GUARD(s2n_stuffer_write_uint16(&supported_groups_extension, ec_curves_count * 2));
        for (int i = 0; i < ec_curves_count; i++) {
            GUARD(s2n_stuffer_write_uint16(&supported_groups_extension, unsupported_curves[i].iana_id));
        }

        /* Create a properly parsed client hello extension using the stuffer's blob */
        struct s2n_array *parsed_extensions = s2n_array_new(sizeof(struct s2n_client_hello_parsed_extension));
        struct s2n_client_hello_parsed_extension *parsed_named_group_extension = s2n_array_pushback(parsed_extensions);
        parsed_named_group_extension->extension_type = TLS_EXTENSION_SUPPORTED_GROUPS;
        parsed_named_group_extension->extension = supported_groups_extension.blob;

        /* Force a bad value for the negotiated curve so we know extension was parsed and the curve was set to NULL */
        struct s2n_ecc_named_curve invalid_curve = { 0 };
        conn->secure.server_ecc_evp_params.negotiated_curve = &invalid_curve;
        EXPECT_SUCCESS(s2n_client_extensions_recv(conn, parsed_extensions));
        EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);

        EXPECT_SUCCESS(s2n_stuffer_free(&supported_groups_extension));
        EXPECT_SUCCESS(s2n_array_free(parsed_extensions));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    END_TEST();
    return 0;
}
