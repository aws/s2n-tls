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

#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"

#define S2N_TEST_PSK_VALUE "psk_test"

struct s2n_psk *s2n_test_psk_new(struct s2n_connection *conn)
{
    PTR_ENSURE_REF(conn);

    /* We're assuming the index will only take one digit */
    uint8_t buffer[sizeof(S2N_TEST_PSK_VALUE) + 1] = { 0 };
    int r = snprintf((char *) buffer, sizeof(buffer), "%s%u", S2N_TEST_PSK_VALUE, conn->psk_params.psk_list.len);
    PTR_ENSURE_GT(r, 0);
    PTR_ENSURE_LT(r, sizeof(buffer));

    DEFER_CLEANUP(struct s2n_psk *psk = s2n_external_psk_new(), s2n_psk_free);
    PTR_GUARD_POSIX(s2n_psk_set_identity(psk, buffer, sizeof(buffer)));
    PTR_GUARD_POSIX(s2n_psk_set_secret(psk, buffer, sizeof(buffer)));

    struct s2n_psk *result_psk = psk;
    ZERO_TO_DISABLE_DEFER_CLEANUP(psk);
    return result_psk;
}

S2N_RESULT s2n_append_test_psk_with_early_data(struct s2n_connection *conn, uint32_t max_early_data,
        const struct s2n_cipher_suite *cipher_suite)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(cipher_suite);

    DEFER_CLEANUP(struct s2n_psk *psk = s2n_test_psk_new(conn), s2n_psk_free);
    psk->hmac_alg = cipher_suite->prf_alg;
    if (max_early_data > 0) {
        RESULT_GUARD_POSIX(s2n_psk_configure_early_data(psk, max_early_data,
                cipher_suite->iana_value[0], cipher_suite->iana_value[1]));
    }
    RESULT_GUARD_POSIX(s2n_connection_append_psk(conn, psk));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_append_test_chosen_psk_with_early_data(struct s2n_connection *conn, uint32_t max_early_data,
        const struct s2n_cipher_suite *cipher_suite)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(cipher_suite);

    RESULT_GUARD(s2n_append_test_psk_with_early_data(conn, max_early_data, cipher_suite));
    RESULT_ENSURE_GT(conn->psk_params.psk_list.len, 0);

    struct s2n_psk *last_psk = NULL;
    RESULT_GUARD(s2n_array_get(&conn->psk_params.psk_list, conn->psk_params.psk_list.len - 1, (void **) &last_psk));
    conn->psk_params.chosen_psk = last_psk;

    return S2N_RESULT_OK;
}
