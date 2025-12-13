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

#include "utils/s2n_events.h"

#include <math.h>
#include <stdlib.h>

#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

struct event_subscriber {
    uint64_t invoked;
};

void subscriber_on_handshake_complete(
        struct s2n_connection *conn,
        void *subscriber,
        struct s2n_event_handshake *event)
{
    struct event_subscriber *sub = (struct event_subscriber *) subscriber;
    sub->invoked++;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
    struct event_subscriber subscriber = { 0 };
    s2n_config_set_subscriber(config, &subscriber);
    s2n_config_set_handshake_event(config, subscriber_on_handshake_complete);

    DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
    s2n_connection_set_config(conn, config);

    /* setup connection fields for s2n_event_handshake_populate */
    conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256;
    conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp521r1;
    conn->actual_protocol_version = S2N_TLS12;

    /* s2n_event_handshake_populate: group, cipher, and protocol version are complete */
    {
        struct s2n_event_handshake event = { 0 };
        EXPECT_OK(s2n_event_handshake_populate(conn, &event));
        EXPECT_EQUAL(strcmp(event.cipher, "ECDHE-ECDSA-CHACHA20-POLY1305"), 0);
        EXPECT_EQUAL(strcmp(event.group, "secp521r1"), 0);
        EXPECT_EQUAL(event.protocol_version, S2N_TLS12);
        /* we don't expect handshake_populate to touch the time */
        EXPECT_EQUAL(event.handshake_end_ns, 0);
        EXPECT_EQUAL(event.handshake_start_ns, 0);
        EXPECT_EQUAL(event.handshake_time_ns, 0);
    };

    /* s2n_event_handshake_send: callback is invoked */
    {
        struct s2n_event_handshake event = { 0 };
        EXPECT_OK(s2n_event_handshake_send(conn, &event));
        EXPECT_EQUAL(subscriber.invoked, 1);
        EXPECT_EQUAL(event.handshake_start_ns, HANDSHAKE_EVENT_SENT);

        /* idempotency: calling handshake_send again will not 
         * invoke the callback */
        EXPECT_OK(s2n_event_handshake_send(conn, &event));
        EXPECT_EQUAL(subscriber.invoked, 1);
    }

    END_TEST();
}
