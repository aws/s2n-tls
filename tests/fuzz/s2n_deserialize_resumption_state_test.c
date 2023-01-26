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

/* Target Functions: s2n_deserialize_resumption_state
 * This test fuzzes the deserialization logic for our session tickets. This occurs after
 * the ticket has been decrypted with the server ticket key. Technically it's not
 * necessary to fuzz decrypted values, however, in the event that an attacker is 
 * able to get a valid ticket key, we want to make sure these functions can't cause damage.
 */

#include "api/s2n.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_resume.h"
#include "utils/s2n_safety.h"

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
    /* We need at least one byte of input to set parameters */
    S2N_FUZZ_ENSURE_MIN_LEN(len, 1);

    DEFER_CLEANUP(struct s2n_stuffer fuzzed_ticket = { 0 }, s2n_stuffer_free);
    POSIX_GUARD(s2n_stuffer_alloc(&fuzzed_ticket, len));
    POSIX_GUARD(s2n_stuffer_write_bytes(&fuzzed_ticket, buf, len));

    /* Pull a byte off the libfuzzer input and use it to set parameters */
    uint8_t randval = 0;
    POSIX_GUARD(s2n_stuffer_read_uint8(&fuzzed_ticket, &randval));
    POSIX_GUARD(s2n_stuffer_reread(&fuzzed_ticket));
    POSIX_GUARD(s2n_stuffer_rewrite(&fuzzed_ticket));

    /* There are only a few valid formats for session tickets; this ensures the
     * format version is at or below S2N_SERIALIZED_FORMAT_TLS12_V3, which will
     * keep the test checking mostly valid paths. */
    randval = randval % S2N_SERIALIZED_FORMAT_TLS12_V3;
    POSIX_GUARD(s2n_stuffer_write_uint8(&fuzzed_ticket, randval));
    /* We have to put the write cursor back */
    POSIX_GUARD(s2n_stuffer_skip_write(&fuzzed_ticket, len - 1));

    /* A session ticket is sent along with the Client Hello, so there's not much set up needed for the server */
    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
    POSIX_ENSURE_REF(server_conn);
    POSIX_GUARD(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

    uint8_t test_data[] = "test psk identity";
    struct s2n_blob test_blob = { 0 };
    POSIX_GUARD(s2n_blob_init(&test_blob, test_data, sizeof(test_data)));

    /* Ignore the result of this function */
    s2n_result_ignore(s2n_deserialize_resumption_state(server_conn, &test_blob, &fuzzed_ticket));

    return S2N_SUCCESS;
}

S2N_FUZZ_TARGET(NULL, s2n_fuzz_test, NULL)
