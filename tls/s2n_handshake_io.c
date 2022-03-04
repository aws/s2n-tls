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

#include <errno.h>
#include "api/s2n.h"

#include "error/s2n_errno.h"

#include "crypto/s2n_fips.h"

#include "tls/s2n_async_pkey.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_record.h"
#include "tls/s2n_resume.h"
#include "tls/s2n_alerts.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"
#include "tls/s2n_tls13_key_schedule.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_post_handshake.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_socket.h"
#include "utils/s2n_random.h"
#include "utils/s2n_bitmap.h"

/* clang-format off */
struct s2n_handshake_action {
    uint8_t record_type;
    uint8_t message_type;
    char writer;                /* 'S' or 'C' for server or client, 'B' for both */
    int (*handler[2]) (struct s2n_connection * conn);
};

static int s2n_always_fail_send(struct s2n_connection *conn)
{
    /* This state should never be sending a handshake message. */
    POSIX_BAIL(S2N_ERR_HANDSHAKE_UNREACHABLE);
}

static int s2n_always_fail_recv(struct s2n_connection *conn)
{
    /* This state should never have an incoming handshake message. */
    POSIX_BAIL(S2N_ERR_HANDSHAKE_UNREACHABLE);
}

/* Client and Server handlers for each message type we support.  
 * See http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7 for the list of handshake message types
 */
static struct s2n_handshake_action state_machine[] = {
    /* message_type_t           = {Record type   Message type     Writer S2N_SERVER                S2N_CLIENT }  */
    [CLIENT_HELLO]              = {TLS_HANDSHAKE, TLS_CLIENT_HELLO, 'C', {s2n_establish_session, s2n_client_hello_send}},
    [SERVER_HELLO]              = {TLS_HANDSHAKE, TLS_SERVER_HELLO, 'S', {s2n_server_hello_send, s2n_server_hello_recv}},
    [SERVER_NEW_SESSION_TICKET] = {TLS_HANDSHAKE, TLS_SERVER_NEW_SESSION_TICKET,'S', {s2n_server_nst_send, s2n_server_nst_recv}},
    [SERVER_CERT]               = {TLS_HANDSHAKE, TLS_CERTIFICATE, 'S', {s2n_server_cert_send, s2n_server_cert_recv}},
    [SERVER_CERT_STATUS]        = {TLS_HANDSHAKE, TLS_SERVER_CERT_STATUS, 'S', {s2n_server_status_send, s2n_server_status_recv}},
    [SERVER_KEY]                = {TLS_HANDSHAKE, TLS_SERVER_KEY, 'S', {s2n_server_key_send, s2n_server_key_recv}},
    [SERVER_CERT_REQ]           = {TLS_HANDSHAKE, TLS_CERT_REQ, 'S', {s2n_cert_req_send, s2n_cert_req_recv}},
    [SERVER_HELLO_DONE]         = {TLS_HANDSHAKE, TLS_SERVER_HELLO_DONE, 'S', {s2n_server_done_send, s2n_server_done_recv}},
    [CLIENT_CERT]               = {TLS_HANDSHAKE, TLS_CERTIFICATE, 'C', {s2n_client_cert_recv, s2n_client_cert_send}},
    [CLIENT_KEY]                = {TLS_HANDSHAKE, TLS_CLIENT_KEY, 'C', {s2n_client_key_recv, s2n_client_key_send}},
    [CLIENT_CERT_VERIFY]        = {TLS_HANDSHAKE, TLS_CERT_VERIFY, 'C', {s2n_client_cert_verify_recv, s2n_client_cert_verify_send}},
    [CLIENT_CHANGE_CIPHER_SPEC] = {TLS_CHANGE_CIPHER_SPEC, 0, 'C', {s2n_client_ccs_recv, s2n_ccs_send}},
    [CLIENT_FINISHED]           = {TLS_HANDSHAKE, TLS_FINISHED, 'C', {s2n_client_finished_recv, s2n_client_finished_send}},
    [SERVER_CHANGE_CIPHER_SPEC] = {TLS_CHANGE_CIPHER_SPEC, 0, 'S', {s2n_ccs_send, s2n_server_ccs_recv}},
    [SERVER_FINISHED]           = {TLS_HANDSHAKE, TLS_FINISHED, 'S', {s2n_server_finished_send, s2n_server_finished_recv}},
    [APPLICATION_DATA]          = {TLS_APPLICATION_DATA, 0, 'B', {s2n_always_fail_send, s2n_always_fail_recv}}
};

/*
 * Client and Server handlers for TLS1.3.
 */
static struct s2n_handshake_action tls13_state_machine[] = {
    /* message_type_t           = {Record type, Message type, Writer, {Server handler, client handler} }  */
    [CLIENT_HELLO]              = {TLS_HANDSHAKE, TLS_CLIENT_HELLO, 'C', {s2n_establish_session, s2n_client_hello_send}},
    [SERVER_HELLO]              = {TLS_HANDSHAKE, TLS_SERVER_HELLO, 'S', {s2n_server_hello_send, s2n_server_hello_recv}},
    [HELLO_RETRY_MSG]           = {TLS_HANDSHAKE, TLS_SERVER_HELLO, 'S', {s2n_server_hello_retry_send, s2n_server_hello_retry_recv}},
    [ENCRYPTED_EXTENSIONS]      = {TLS_HANDSHAKE, TLS_ENCRYPTED_EXTENSIONS, 'S', {s2n_encrypted_extensions_send, s2n_encrypted_extensions_recv}},
    [SERVER_CERT_REQ]           = {TLS_HANDSHAKE, TLS_CERT_REQ, 'S', {s2n_tls13_cert_req_send, s2n_tls13_cert_req_recv}},
    [SERVER_CERT]               = {TLS_HANDSHAKE, TLS_CERTIFICATE, 'S', {s2n_server_cert_send, s2n_server_cert_recv}},
    [SERVER_CERT_VERIFY]        = {TLS_HANDSHAKE, TLS_CERT_VERIFY, 'S', {s2n_tls13_cert_verify_send, s2n_tls13_cert_verify_recv}},
    [SERVER_FINISHED]           = {TLS_HANDSHAKE, TLS_FINISHED, 'S', {s2n_tls13_server_finished_send, s2n_tls13_server_finished_recv}},

    [CLIENT_CERT]               = {TLS_HANDSHAKE, TLS_CERTIFICATE, 'C', {s2n_client_cert_recv, s2n_client_cert_send}},
    [CLIENT_CERT_VERIFY]        = {TLS_HANDSHAKE, TLS_CERT_VERIFY, 'C', {s2n_tls13_cert_verify_recv, s2n_tls13_cert_verify_send}},
    [CLIENT_FINISHED]           = {TLS_HANDSHAKE, TLS_FINISHED, 'C', {s2n_tls13_client_finished_recv, s2n_tls13_client_finished_send}},
    [END_OF_EARLY_DATA]         = {TLS_HANDSHAKE, TLS_END_OF_EARLY_DATA, 'C', {s2n_end_of_early_data_recv, s2n_end_of_early_data_send}},

    /* Not used by TLS1.3, except to maintain middlebox compatibility */
    [CLIENT_CHANGE_CIPHER_SPEC] = {TLS_CHANGE_CIPHER_SPEC, 0, 'C', {s2n_basic_ccs_recv, s2n_ccs_send}},
    [SERVER_CHANGE_CIPHER_SPEC] = {TLS_CHANGE_CIPHER_SPEC, 0, 'S', {s2n_ccs_send, s2n_basic_ccs_recv}},

    [APPLICATION_DATA]          = {TLS_APPLICATION_DATA, 0, 'B', {s2n_always_fail_send, s2n_always_fail_recv}},
};

#define MESSAGE_NAME_ENTRY(msg) [msg] = #msg

static const char *message_names[] = {
    MESSAGE_NAME_ENTRY(CLIENT_HELLO),
    MESSAGE_NAME_ENTRY(SERVER_HELLO),
    MESSAGE_NAME_ENTRY(ENCRYPTED_EXTENSIONS),
    MESSAGE_NAME_ENTRY(SERVER_NEW_SESSION_TICKET),
    MESSAGE_NAME_ENTRY(SERVER_CERT),
    MESSAGE_NAME_ENTRY(SERVER_CERT_STATUS),
    MESSAGE_NAME_ENTRY(SERVER_CERT_VERIFY),
    MESSAGE_NAME_ENTRY(SERVER_KEY),
    MESSAGE_NAME_ENTRY(SERVER_CERT_REQ),
    MESSAGE_NAME_ENTRY(SERVER_HELLO_DONE),
    MESSAGE_NAME_ENTRY(CLIENT_CERT),
    MESSAGE_NAME_ENTRY(CLIENT_KEY),
    MESSAGE_NAME_ENTRY(CLIENT_CERT_VERIFY),
    MESSAGE_NAME_ENTRY(CLIENT_CHANGE_CIPHER_SPEC),
    MESSAGE_NAME_ENTRY(CLIENT_FINISHED),
    MESSAGE_NAME_ENTRY(SERVER_CHANGE_CIPHER_SPEC),
    MESSAGE_NAME_ENTRY(SERVER_FINISHED),
    MESSAGE_NAME_ENTRY(HELLO_RETRY_MSG),
    MESSAGE_NAME_ENTRY(END_OF_EARLY_DATA),
    MESSAGE_NAME_ENTRY(APPLICATION_DATA),
};

/* Maximum number of messages in a handshake */
#define S2N_MAX_HANDSHAKE_LENGTH    32

/* We support different ordering of TLS Handshake messages, depending on what is being negotiated. There's also a dummy "INITIAL" handshake
 * that everything starts out as until we know better.
 */

static message_type_t handshakes[S2N_HANDSHAKES_COUNT][S2N_MAX_HANDSHAKE_LENGTH] = {
    [INITIAL] = {
            CLIENT_HELLO,
            SERVER_HELLO
    },

    [NEGOTIATED] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | WITH_SESSION_TICKET ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            APPLICATION_DATA},

    [NEGOTIATED | FULL_HANDSHAKE ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | WITH_SESSION_TICKET ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY | WITH_SESSION_TICKET ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | OCSP_STATUS ] ={
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | OCSP_STATUS | WITH_SESSION_TICKET ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY | OCSP_STATUS ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_KEY, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY | OCSP_STATUS  | WITH_SESSION_TICKET ] ={
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_KEY, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | NO_CLIENT_CERT ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | WITH_SESSION_TICKET] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | NO_CLIENT_CERT | WITH_SESSION_TICKET ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY | CLIENT_AUTH] = {
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY | CLIENT_AUTH | NO_CLIENT_CERT ] = {
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY | CLIENT_AUTH | WITH_SESSION_TICKET] = {
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY | CLIENT_AUTH | NO_CLIENT_CERT | WITH_SESSION_TICKET ] = {
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | OCSP_STATUS | CLIENT_AUTH] = {
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | OCSP_STATUS | CLIENT_AUTH | NO_CLIENT_CERT ] = {
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | OCSP_STATUS | CLIENT_AUTH | WITH_SESSION_TICKET] = {
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | OCSP_STATUS | CLIENT_AUTH | NO_CLIENT_CERT | WITH_SESSION_TICKET ] = {
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY | OCSP_STATUS | CLIENT_AUTH ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY | OCSP_STATUS | CLIENT_AUTH | NO_CLIENT_CERT ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY | OCSP_STATUS | CLIENT_AUTH | WITH_SESSION_TICKET ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | TLS12_PERFECT_FORWARD_SECRECY | OCSP_STATUS | CLIENT_AUTH | NO_CLIENT_CERT | WITH_SESSION_TICKET ] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    },
};

/*
 * This selection of handshakes resembles the standard set, but with changes made to support tls1.3.
 *
 * The CHANGE_CIPHER_SPEC messages are included only for middlebox compatibility.
 * See https://tools.ietf.org/html/rfc8446#appendix-D.4
 */
static message_type_t tls13_handshakes[S2N_HANDSHAKES_COUNT][S2N_MAX_HANDSHAKE_LENGTH] = {
    [INITIAL] = {
            CLIENT_HELLO,
            SERVER_HELLO
    },

    [INITIAL | MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS] = {
            CLIENT_HELLO, CLIENT_CHANGE_CIPHER_SPEC,
            SERVER_HELLO
    },

    [INITIAL | HELLO_RETRY_REQUEST] = {
            CLIENT_HELLO,
            HELLO_RETRY_MSG
    },

    [INITIAL | HELLO_RETRY_REQUEST | MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS] = {
            CLIENT_HELLO, CLIENT_CHANGE_CIPHER_SPEC,
            HELLO_RETRY_MSG
    },

    [NEGOTIATED] = {
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_FINISHED,
            CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | WITH_EARLY_DATA] = {
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_FINISHED,
            END_OF_EARLY_DATA, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | MIDDLEBOX_COMPAT] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_FINISHED,
            CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS] = {
            CLIENT_HELLO, CLIENT_CHANGE_CIPHER_SPEC,
            SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_FINISHED,
            CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | MIDDLEBOX_COMPAT | WITH_EARLY_DATA] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_FINISHED,
            CLIENT_CHANGE_CIPHER_SPEC, END_OF_EARLY_DATA, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS | WITH_EARLY_DATA] = {
            CLIENT_HELLO, CLIENT_CHANGE_CIPHER_SPEC,
            SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_FINISHED,
            END_OF_EARLY_DATA, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | HELLO_RETRY_REQUEST] = {
            CLIENT_HELLO,
            HELLO_RETRY_MSG,
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_FINISHED,
            CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | HELLO_RETRY_REQUEST | MIDDLEBOX_COMPAT] = {
            CLIENT_HELLO,
            HELLO_RETRY_MSG, SERVER_CHANGE_CIPHER_SPEC,
            CLIENT_CHANGE_CIPHER_SPEC, CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_FINISHED,
            CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | HELLO_RETRY_REQUEST | MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS] = {
            CLIENT_HELLO, CLIENT_CHANGE_CIPHER_SPEC,
            HELLO_RETRY_MSG, SERVER_CHANGE_CIPHER_SPEC,
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_FINISHED,
            CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE] = {
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | MIDDLEBOX_COMPAT] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS] = {
            CLIENT_HELLO, CLIENT_CHANGE_CIPHER_SPEC,
            SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST] = {
            CLIENT_HELLO,
            HELLO_RETRY_MSG,
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST | MIDDLEBOX_COMPAT] = {
            CLIENT_HELLO,
            HELLO_RETRY_MSG, SERVER_CHANGE_CIPHER_SPEC,
            CLIENT_CHANGE_CIPHER_SPEC, CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST | MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS] = {
            CLIENT_HELLO, CLIENT_CHANGE_CIPHER_SPEC,
            HELLO_RETRY_MSG, SERVER_CHANGE_CIPHER_SPEC,
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST | CLIENT_AUTH] = {
            CLIENT_HELLO,
            HELLO_RETRY_MSG,
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CERT, CLIENT_CERT_VERIFY, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST | CLIENT_AUTH | MIDDLEBOX_COMPAT] = {
            CLIENT_HELLO,
            HELLO_RETRY_MSG, SERVER_CHANGE_CIPHER_SPEC,
            CLIENT_CHANGE_CIPHER_SPEC, CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CERT, CLIENT_CERT_VERIFY, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST | CLIENT_AUTH | MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS] = {
            CLIENT_HELLO, CLIENT_CHANGE_CIPHER_SPEC,
            HELLO_RETRY_MSG, SERVER_CHANGE_CIPHER_SPEC,
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CERT, CLIENT_CERT_VERIFY, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST | CLIENT_AUTH | NO_CLIENT_CERT] = {
            CLIENT_HELLO,
            HELLO_RETRY_MSG,
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CERT, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST | CLIENT_AUTH | NO_CLIENT_CERT | MIDDLEBOX_COMPAT] = {
            CLIENT_HELLO,
            HELLO_RETRY_MSG, SERVER_CHANGE_CIPHER_SPEC,
            CLIENT_CHANGE_CIPHER_SPEC, CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CERT, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST | CLIENT_AUTH | NO_CLIENT_CERT | MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS] = {
            CLIENT_HELLO, CLIENT_CHANGE_CIPHER_SPEC,
            HELLO_RETRY_MSG, SERVER_CHANGE_CIPHER_SPEC,
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CERT, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH] = {
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CERT, CLIENT_CERT_VERIFY, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | MIDDLEBOX_COMPAT] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CHANGE_CIPHER_SPEC, CLIENT_CERT, CLIENT_CERT_VERIFY, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS] = {
            CLIENT_HELLO, CLIENT_CHANGE_CIPHER_SPEC,
            SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CERT, CLIENT_CERT_VERIFY, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | NO_CLIENT_CERT] = {
            CLIENT_HELLO,
            SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CERT, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | NO_CLIENT_CERT | MIDDLEBOX_COMPAT] = {
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CHANGE_CIPHER_SPEC, CLIENT_CERT, CLIENT_FINISHED,
            APPLICATION_DATA
    },

    [NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | NO_CLIENT_CERT | MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS] = {
            CLIENT_HELLO, CLIENT_CHANGE_CIPHER_SPEC,
            SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
            CLIENT_CERT, CLIENT_FINISHED,
            APPLICATION_DATA
    },
};
/* clang-format on */

#define MAX_HANDSHAKE_TYPE_LEN 123
static char handshake_type_str[S2N_HANDSHAKES_COUNT][MAX_HANDSHAKE_TYPE_LEN] = {0};

static const char* tls12_handshake_type_names[] = {
    "NEGOTIATED|",
    "FULL_HANDSHAKE|",
    "CLIENT_AUTH|",
    "NO_CLIENT_CERT|",
    "TLS12_PERFECT_FORWARD_SECRECY|",
    "OCSP_STATUS|",
    "WITH_SESSION_TICKET|",
};

static const char* tls13_handshake_type_names[] = {
    "NEGOTIATED|",
    "FULL_HANDSHAKE|",
    "CLIENT_AUTH|",
    "NO_CLIENT_CERT|",
    "HELLO_RETRY_REQUEST|",
    "MIDDLEBOX_COMPAT|",
    "WITH_EARLY_DATA|",
    "EARLY_CLIENT_CCS|",
};

#define IS_TLS13_HANDSHAKE( conn )    ((conn)->actual_protocol_version == S2N_TLS13)

#define ACTIVE_STATE_MACHINE( conn )  (IS_TLS13_HANDSHAKE(conn) ? tls13_state_machine : state_machine)
#define ACTIVE_HANDSHAKES( conn )     (IS_TLS13_HANDSHAKE(conn) ? tls13_handshakes : handshakes)

#define ACTIVE_MESSAGE( conn )        ACTIVE_HANDSHAKES(conn)[ (conn)->handshake.handshake_type ][ (conn)->handshake.message_number ]

#define ACTIVE_STATE( conn )          ACTIVE_STATE_MACHINE(conn)[ ACTIVE_MESSAGE( (conn) ) ]
#define CCS_STATE( conn )             (((conn)->mode == S2N_CLIENT) ? ACTIVE_STATE_MACHINE(conn)[SERVER_CHANGE_CIPHER_SPEC] \
                                                                    : ACTIVE_STATE_MACHINE(conn)[CLIENT_CHANGE_CIPHER_SPEC] )

#define EXPECTED_RECORD_TYPE( conn )  ACTIVE_STATE( conn ).record_type
#define EXPECTED_MESSAGE_TYPE( conn ) ACTIVE_STATE( conn ).message_type

#define CONNECTION_WRITER( conn ) (conn->mode == S2N_CLIENT ? 'C' : 'S')
#define CONNECTION_IS_WRITER( conn ) (ACTIVE_STATE(conn).writer == CONNECTION_WRITER(conn))

/* Only used in our test cases. */
message_type_t s2n_conn_get_current_message_type(struct s2n_connection *conn)
{
    return ACTIVE_MESSAGE(conn);
}

static int s2n_advance_message(struct s2n_connection *conn)
{
    /* Get the mode: 'C'lient or 'S'erver */
    char previous_writer = ACTIVE_STATE(conn).writer;
    char this_mode = CONNECTION_WRITER(conn);

    /* Actually advance the message number */
    conn->handshake.message_number++;

    /* When reading and using TLS1.3, skip optional change_cipher_spec states. */
    if (ACTIVE_STATE(conn).writer != this_mode &&
            EXPECTED_RECORD_TYPE(conn) == TLS_CHANGE_CIPHER_SPEC &&
            IS_TLS13_HANDSHAKE(conn)) {
        conn->handshake.message_number++;
    }

    /* Set TCP_QUICKACK to avoid artificial delay during the handshake */
    POSIX_GUARD(s2n_socket_quickack(conn));

    /* If optimized io hasn't been enabled or if the caller started out with a corked socket,
     * we don't mess with it
     */
    if (!conn->corked_io || s2n_socket_was_corked(conn)) {
        return S2N_SUCCESS;
    }

    /* Are we changing I/O directions */
    if (ACTIVE_STATE(conn).writer == previous_writer || ACTIVE_STATE(conn).writer == 'A') {
        return S2N_SUCCESS;
    }

    /* We're the new writer */
    if (ACTIVE_STATE(conn).writer == this_mode) {
        if (s2n_connection_is_managed_corked(conn)) {
            /* Set TCP_CORK/NOPUSH */
            POSIX_GUARD(s2n_socket_write_cork(conn));
        }

        return S2N_SUCCESS;
    }

    /* We're the new reader, or we reached the "B" writer stage indicating that
       we're at the application data stage  - uncork the data */
    if (s2n_connection_is_managed_corked(conn)) {
        POSIX_GUARD(s2n_socket_write_uncork(conn));
    }

    return S2N_SUCCESS;
}

int s2n_generate_new_client_session_id(struct s2n_connection *conn)
{
    if (conn->mode == S2N_SERVER) {
        struct s2n_blob session_id = { .data = conn->session_id, .size = S2N_TLS_SESSION_ID_MAX_LEN };

        /* Generate a new session id */
        POSIX_GUARD_RESULT(s2n_get_public_random_data(&session_id));
        conn->session_id_len = S2N_TLS_SESSION_ID_MAX_LEN;
    }

    return S2N_SUCCESS;
}

/* Lets the server flag whether a HelloRetryRequest is needed while processing extensions */
int s2n_set_hello_retry_required(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    POSIX_ENSURE(conn->actual_protocol_version >= S2N_TLS13, S2N_ERR_INVALID_HELLO_RETRY);
    POSIX_GUARD_RESULT(s2n_handshake_type_set_tls13_flag(conn, HELLO_RETRY_REQUEST));

    /* HelloRetryRequests also indicate rejection of early data.
     *
     *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
     *# A server which receives an "early_data" extension MUST behave in one
     *# of three ways:
     *
     *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
     *# -  Request that the client send another ClientHello by responding
     *#    with a HelloRetryRequest.
     **/
    if (conn->early_data_state == S2N_EARLY_DATA_REQUESTED) {
        POSIX_GUARD_RESULT(s2n_connection_set_early_data_state(conn, S2N_EARLY_DATA_REJECTED));
    }

    return S2N_SUCCESS;
}

bool s2n_is_hello_retry_message(struct s2n_connection *conn)
{
    return (conn != NULL &&
            s2n_result_is_ok(s2n_handshake_validate(&(conn->handshake))) &&
            ACTIVE_MESSAGE(conn) == HELLO_RETRY_MSG);
}

bool s2n_is_hello_retry_handshake(struct s2n_connection *conn)
{
    return IS_HELLO_RETRY_HANDSHAKE(conn);
}

static S2N_RESULT s2n_conn_set_tls13_handshake_type(struct s2n_connection *conn) {
    RESULT_ENSURE_REF(conn);

    /* Most handshake type flags should be reset before we calculate the handshake type,
     * in order to handle changes during retries.
     * However, flags that have already affected the message order must be kept to avoid
     * rewriting the past.
     */
    conn->handshake.handshake_type &= (HELLO_RETRY_REQUEST | MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS);

    /* A handshake type has been negotiated */
    RESULT_GUARD(s2n_handshake_type_set_flag(conn, NEGOTIATED));

    if (conn->psk_params.chosen_psk == NULL) {
        RESULT_GUARD(s2n_handshake_type_set_flag(conn, FULL_HANDSHAKE));
    }

    if (conn->early_data_state == S2N_EARLY_DATA_ACCEPTED) {
        conn->handshake.handshake_type |= WITH_EARLY_DATA;
    }

    s2n_cert_auth_type client_cert_auth_type;
    RESULT_GUARD_POSIX(s2n_connection_get_client_auth_type(conn, &client_cert_auth_type));

    if (conn->mode == S2N_CLIENT && client_cert_auth_type == S2N_CERT_AUTH_REQUIRED
            && IS_FULL_HANDSHAKE(conn)) {
        /* If we're a client, and Client Auth is REQUIRED, then the Client must expect the CLIENT_CERT_REQ Message */
        RESULT_GUARD(s2n_handshake_type_set_flag(conn, CLIENT_AUTH));
    } else if (conn->mode == S2N_SERVER && client_cert_auth_type != S2N_CERT_AUTH_NONE
            && IS_FULL_HANDSHAKE(conn)) {
        /* If we're a server, and Client Auth is REQUIRED or OPTIONAL, then the server must send the CLIENT_CERT_REQ Message*/
        RESULT_GUARD(s2n_handshake_type_set_flag(conn, CLIENT_AUTH));
    }

    if (s2n_is_middlebox_compat_enabled(conn)) {
        RESULT_GUARD(s2n_handshake_type_set_tls13_flag(conn, MIDDLEBOX_COMPAT));
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_validate_ems_status(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);

    s2n_extension_type_id ems_ext_id = 0;
    RESULT_GUARD_POSIX(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_EMS, &ems_ext_id));
    bool ems_extension_recv = S2N_CBIT_TEST(conn->extension_requests_received, ems_ext_id);

    /**
     *= https://tools.ietf.org/rfc/rfc7627#section-5.3
     *# If the original session used the "extended_master_secret"
     *# extension but the new ClientHello does not contain it, the server
     *# MUST abort the abbreviated handshake.
     **/
    if (conn->ems_negotiated) {
        RESULT_ENSURE(ems_extension_recv, S2N_ERR_MISSING_EXTENSION);
    }

    /* Since we're discarding the resumption ticket, ignore EMS value from the ticket */
    conn->ems_negotiated = ems_extension_recv;

    return S2N_RESULT_OK;
}

int s2n_conn_set_handshake_type(struct s2n_connection *conn)
{
    if (IS_TLS13_HANDSHAKE(conn)) {
        POSIX_GUARD_RESULT(s2n_conn_set_tls13_handshake_type(conn));
        return S2N_SUCCESS;
    }

    POSIX_GUARD_RESULT(s2n_handshake_type_reset(conn));

    /* A handshake type has been negotiated */
    POSIX_GUARD_RESULT(s2n_handshake_type_set_flag(conn, NEGOTIATED));

    s2n_cert_auth_type client_cert_auth_type;
    POSIX_GUARD(s2n_connection_get_client_auth_type(conn, &client_cert_auth_type));

    if (conn->mode == S2N_CLIENT && client_cert_auth_type == S2N_CERT_AUTH_REQUIRED) {
        /* If we're a client, and Client Auth is REQUIRED, then the Client must expect the CLIENT_CERT_REQ Message */
        POSIX_GUARD_RESULT(s2n_handshake_type_set_flag(conn, CLIENT_AUTH));
    } else if (conn->mode == S2N_SERVER && client_cert_auth_type != S2N_CERT_AUTH_NONE) {
        /* If we're a server, and Client Auth is REQUIRED or OPTIONAL, then the server must send the CLIENT_CERT_REQ Message*/
        POSIX_GUARD_RESULT(s2n_handshake_type_set_flag(conn, CLIENT_AUTH));
    }

    if (conn->config->use_tickets) {
        if (conn->session_ticket_status == S2N_DECRYPT_TICKET) {
            if (s2n_decrypt_session_ticket(conn, &conn->client_ticket_to_decrypt) == S2N_SUCCESS) {
                return S2N_SUCCESS;
            }

            POSIX_GUARD_RESULT(s2n_validate_ems_status(conn));

            if (s2n_config_is_encrypt_decrypt_key_available(conn->config) == 1) {
                conn->session_ticket_status = S2N_NEW_TICKET;
                POSIX_GUARD_RESULT(s2n_handshake_type_set_tls12_flag(conn, WITH_SESSION_TICKET));
            }

            /* If a session ticket is presented by the client, then skip lookup in Session ID server cache */
            goto skip_cache_lookup;
        }

        if (conn->session_ticket_status == S2N_NEW_TICKET) {
            POSIX_GUARD_RESULT(s2n_handshake_type_set_tls12_flag(conn, WITH_SESSION_TICKET));
        }
    }

    /* If a TLS session is resumed, the Server should respond in its ServerHello with the same SessionId the
     * Client sent in the ClientHello. */
    if (conn->actual_protocol_version <= S2N_TLS12 && conn->mode == S2N_SERVER && s2n_allowed_to_cache_connection(conn)) {
        int r = s2n_resume_from_cache(conn);
        if (r == S2N_SUCCESS || (r < S2N_SUCCESS && S2N_ERROR_IS_BLOCKING(s2n_errno))) {
            return r;
        }
        POSIX_GUARD_RESULT(s2n_validate_ems_status(conn));
    }

skip_cache_lookup:
    if (conn->mode == S2N_CLIENT && conn->client_session_resumed == 1) {
        return S2N_SUCCESS;
    }

    /* If we're doing full handshake, generate a new session id. */
    POSIX_GUARD(s2n_generate_new_client_session_id(conn));

    /* If we get this far, it's a full handshake */
    POSIX_GUARD_RESULT(s2n_handshake_type_set_flag(conn, FULL_HANDSHAKE));

    bool is_ephemeral = false;
    POSIX_GUARD_RESULT(s2n_kex_is_ephemeral(conn->secure.cipher_suite->key_exchange_alg, &is_ephemeral));
    if (is_ephemeral) {
        POSIX_GUARD_RESULT(s2n_handshake_type_set_tls12_flag(conn, TLS12_PERFECT_FORWARD_SECRECY));
    }

    if (s2n_server_can_send_ocsp(conn) || s2n_server_sent_ocsp(conn)) {
        POSIX_GUARD_RESULT(s2n_handshake_type_set_tls12_flag(conn, OCSP_STATUS));
    }

    return S2N_SUCCESS;
}

int s2n_conn_set_handshake_no_client_cert(struct s2n_connection *conn)
{
    s2n_cert_auth_type client_cert_auth_type;
    POSIX_GUARD(s2n_connection_get_client_auth_type(conn, &client_cert_auth_type));
    S2N_ERROR_IF(client_cert_auth_type != S2N_CERT_AUTH_OPTIONAL, S2N_ERR_BAD_MESSAGE);

    POSIX_GUARD_RESULT(s2n_handshake_type_set_flag(conn, NO_CLIENT_CERT));

    return S2N_SUCCESS;
}

const char *s2n_connection_get_last_message_name(struct s2n_connection *conn)
{
    PTR_ENSURE_REF(conn);
    PTR_GUARD_RESULT(s2n_handshake_validate(&(conn->handshake)));
    return message_names[ACTIVE_MESSAGE(conn)];
}

const char *s2n_connection_get_handshake_type_name(struct s2n_connection *conn)
{
    PTR_ENSURE_REF(conn);
    PTR_PRECONDITION(s2n_handshake_validate(&(conn->handshake)));

    uint32_t handshake_type = conn->handshake.handshake_type;

    if (handshake_type == INITIAL) {
        return "INITIAL";
    }

    const char** handshake_type_names = tls13_handshake_type_names;
    size_t handshake_type_names_len = s2n_array_len(tls13_handshake_type_names);
    if (s2n_connection_get_protocol_version(conn) < S2N_TLS13) {
        handshake_type_names = tls12_handshake_type_names;
        handshake_type_names_len = s2n_array_len(tls12_handshake_type_names);
    }

    if (handshake_type_str[handshake_type][0] != '\0') {
        return handshake_type_str[handshake_type];
    }

    /* Compute handshake_type_str[handshake_type] by concatenating
     * each applicable handshake_type.
     *
     * Unit tests enforce that the elements of handshake_type_str are always
     * long enough to contain the longest possible valid handshake_type, but
     * for safety we still handle the case where we need to truncate.
     */
    char *p = handshake_type_str[handshake_type];
    size_t remaining = sizeof(handshake_type_str[0]);
    for (size_t i = 0; i < handshake_type_names_len; i++) {
        if (handshake_type & (1 << i)) {
            size_t bytes_to_copy = MIN(remaining, strlen(handshake_type_names[i]));
            PTR_CHECKED_MEMCPY(p, handshake_type_names[i], bytes_to_copy);
            p[bytes_to_copy] = '\0';
            p += bytes_to_copy;
            remaining -= bytes_to_copy;
        }
    }

    if (p != handshake_type_str[handshake_type] && '|' == *(p - 1)) {
        *(p - 1) = '\0';
    }

    return handshake_type_str[handshake_type];
}

/* Writing is relatively straight forward, simply write each message out as a record,
 * we may fragment a message across multiple records, but we never coalesce multiple
 * messages into single records.
 * Precondition: secure outbound I/O has already been flushed
 */
static int s2n_handshake_write_io(struct s2n_connection *conn)
{
    uint8_t record_type = EXPECTED_RECORD_TYPE(conn);
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    /* Populate handshake.io with header/payload for the current state, once.
     * Check wiped instead of s2n_stuffer_data_available to differentiate between the initial call
     * to s2n_handshake_write_io and a repeated call after an EWOULDBLOCK.
     */
    if (s2n_stuffer_is_wiped(&conn->handshake.io)) {
        if (record_type == TLS_HANDSHAKE) {
            POSIX_GUARD(s2n_handshake_write_header(&conn->handshake.io, ACTIVE_STATE(conn).message_type));
        }
        POSIX_GUARD(ACTIVE_STATE(conn).handler[conn->mode] (conn));
        if (record_type == TLS_HANDSHAKE) {
            POSIX_GUARD(s2n_handshake_finish_header(&conn->handshake.io));
        }
    }

    /* Write the handshake data to records in fragment sized chunks */
    struct s2n_blob out = {0};
    while (s2n_stuffer_data_available(&conn->handshake.io) > 0) {
        uint16_t max_payload_size = 0;
        POSIX_GUARD_RESULT(s2n_record_max_write_payload_size(conn, &max_payload_size));
        out.size = MIN(s2n_stuffer_data_available(&conn->handshake.io), max_payload_size);

        out.data = s2n_stuffer_raw_read(&conn->handshake.io, out.size);
        POSIX_ENSURE_REF(out.data);

        if (s2n_connection_is_quic_enabled(conn)) {
            POSIX_GUARD_RESULT(s2n_quic_write_handshake_message(conn, &out));
        } else {
            POSIX_GUARD(s2n_record_write(conn, record_type, &out));
        }

        /* MD5 and SHA sum the handshake data too */
        if (record_type == TLS_HANDSHAKE) {
            POSIX_GUARD(s2n_conn_update_handshake_hashes(conn, &out));
        }

        /* Actually send the record. We could block here. Assume the caller will call flush before coming back. */
        POSIX_GUARD(s2n_flush(conn, &blocked));
    }

    /* We're done sending the last record, reset everything */
    POSIX_GUARD(s2n_stuffer_wipe(&conn->out));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->handshake.io));

    /* Update the secrets, if necessary */
    POSIX_GUARD_RESULT(s2n_tls13_key_schedule_update(conn));

    /* Advance the state machine */
    POSIX_GUARD(s2n_advance_message(conn));

    return S2N_SUCCESS;
}

/*
 * Returns:
 *  1  - more data is needed to complete the handshake message.
 *  0  - we read the whole handshake message.
 * -1  - error processing the handshake message.
 */
static int s2n_read_full_handshake_message(struct s2n_connection *conn, uint8_t *message_type)
{
    uint32_t current_handshake_data = s2n_stuffer_data_available(&conn->handshake.io);
    if (current_handshake_data < TLS_HANDSHAKE_HEADER_LENGTH) {
        /* The message may be so badly fragmented that we don't even read the full header, take
         * what we can and then continue to the next record read iteration.
         */
        if (s2n_stuffer_data_available(&conn->in) < (TLS_HANDSHAKE_HEADER_LENGTH - current_handshake_data)) {
            POSIX_GUARD(s2n_stuffer_copy(&conn->in, &conn->handshake.io, s2n_stuffer_data_available(&conn->in)));
            return 1;
        }

        /* Get the remainder of the header */
        POSIX_GUARD(s2n_stuffer_copy(&conn->in, &conn->handshake.io, (TLS_HANDSHAKE_HEADER_LENGTH - current_handshake_data)));
    }

    uint32_t handshake_message_length;
    POSIX_GUARD(s2n_handshake_parse_header(conn, message_type, &handshake_message_length));

    S2N_ERROR_IF(handshake_message_length > S2N_MAXIMUM_HANDSHAKE_MESSAGE_LENGTH, S2N_ERR_BAD_MESSAGE);

    uint32_t bytes_to_take = handshake_message_length - s2n_stuffer_data_available(&conn->handshake.io);
    bytes_to_take = MIN(bytes_to_take, s2n_stuffer_data_available(&conn->in));

    /* If the record is handshake data, add it to the handshake buffer */
    POSIX_GUARD(s2n_stuffer_copy(&conn->in, &conn->handshake.io, bytes_to_take));

    /* If we have the whole handshake message, then success */
    if (s2n_stuffer_data_available(&conn->handshake.io) == handshake_message_length) {
        return 0;
    }

    /* We don't have the whole message, so we'll need to go again */
    POSIX_GUARD(s2n_stuffer_reread(&conn->handshake.io));

    return 1;
}

static int s2n_handshake_conn_update_hashes(struct s2n_connection *conn)
{
    uint8_t message_type;
    uint32_t handshake_message_length;

    POSIX_GUARD(s2n_stuffer_reread(&conn->handshake.io));
    POSIX_GUARD(s2n_handshake_parse_header(conn, &message_type, &handshake_message_length));

    struct s2n_blob handshake_record = {0};
    handshake_record.data = conn->handshake.io.blob.data;
    handshake_record.size = TLS_HANDSHAKE_HEADER_LENGTH + handshake_message_length;
    POSIX_ENSURE_REF(handshake_record.data);

    /* MD5 and SHA sum the handshake data too */
    POSIX_GUARD(s2n_conn_update_handshake_hashes(conn, &handshake_record));

    return S2N_SUCCESS;
}

static int s2n_handshake_handle_sslv2(struct s2n_connection *conn)
{
    S2N_ERROR_IF(ACTIVE_MESSAGE(conn) != CLIENT_HELLO, S2N_ERR_BAD_MESSAGE);

    /* Add the message to our handshake hashes */
    struct s2n_blob hashed = {.data = conn->header_in.blob.data + 2,.size = 3 };
    POSIX_GUARD(s2n_conn_update_handshake_hashes(conn, &hashed));

    hashed.data = conn->in.blob.data;
    hashed.size = s2n_stuffer_data_available(&conn->in);
    POSIX_GUARD(s2n_conn_update_handshake_hashes(conn, &hashed));

    /* Handle an SSLv2 client hello */
    POSIX_GUARD(s2n_stuffer_copy(&conn->in, &conn->handshake.io, s2n_stuffer_data_available(&conn->in)));
    /* Set the client hello version */
    conn->client_hello_version = S2N_SSLv2;
    /* Execute the state machine handler */
    int r = ACTIVE_STATE(conn).handler[conn->mode](conn);
    POSIX_GUARD(s2n_stuffer_wipe(&conn->handshake.io));

    /* We're done with the record, wipe it */
    POSIX_GUARD(s2n_stuffer_wipe(&conn->header_in));
    POSIX_GUARD(s2n_stuffer_wipe(&conn->in));

    WITH_ERROR_BLINDING(conn, POSIX_GUARD(r));

    conn->in_status = ENCRYPTED;

    /* Advance the state machine */
    POSIX_GUARD(s2n_advance_message(conn));

    return S2N_SUCCESS;
}

static int s2n_try_delete_session_cache(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    if (s2n_allowed_to_cache_connection(conn) > 0) {
        conn->config->cache_delete(conn, conn->config->cache_delete_data, conn->session_id, conn->session_id_len);
    }

    return S2N_SUCCESS;
}

static S2N_RESULT s2n_wipe_record(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&conn->header_in));
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&conn->in));
    conn->in_status = ENCRYPTED;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_finish_read(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);

    RESULT_GUARD_POSIX(s2n_handshake_conn_update_hashes(conn));
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&conn->handshake.io));
    RESULT_GUARD(s2n_tls13_key_schedule_update(conn));
    RESULT_GUARD_POSIX(s2n_advance_message(conn));
    return S2N_RESULT_OK;
}

/* Reading is a little more complicated than writing as the TLS RFCs allow content
 * types to be interleaved at the record layer. We may get an alert message
 * during the handshake phase, or messages of types that we don't support (e.g.
 * HEARTBEAT messages), or during renegotiations we may even get application
 * data messages that need to be handled by the application. The latter is punted
 * for now (s2n does not support renegotiations).
 */
static int s2n_handshake_read_io(struct s2n_connection *conn)
{
    uint8_t record_type;
    uint8_t message_type;
    int isSSLv2 = 0;

    /* Fill conn->in stuffer necessary for the handshake.
     * If using TCP, read a record. If using QUIC, read a message. */
    if (s2n_connection_is_quic_enabled(conn)) {
        record_type = TLS_HANDSHAKE;
        POSIX_GUARD_RESULT(s2n_quic_read_handshake_message(conn, &message_type));
    } else {
        int r = s2n_read_full_record(conn, &record_type, &isSSLv2);

        /**
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
         *# If the client attempts a 0-RTT handshake but the server
         *# rejects it, the server will generally not have the 0-RTT record
         *# protection keys and must instead use trial decryption (either with
         *# the 1-RTT handshake keys or by looking for a cleartext ClientHello in
         *# the case of a HelloRetryRequest) to find the first non-0-RTT message.
         *#
         *# If the server chooses to accept the "early_data" extension, then it
         *# MUST comply with the same error-handling requirements specified for
         *# all records when processing early data records.  Specifically, if the
         *# server fails to decrypt a 0-RTT record following an accepted
         *# "early_data" extension, it MUST terminate the connection with a
         *# "bad_record_mac" alert as per Section 5.2.
         */
        if ((r < S2N_SUCCESS) && (s2n_errno == S2N_ERR_EARLY_DATA_TRIAL_DECRYPT)) {
            POSIX_GUARD(s2n_stuffer_reread(&conn->in));
            POSIX_GUARD_RESULT(s2n_early_data_record_bytes(conn, s2n_stuffer_data_available(&conn->in)));
            POSIX_GUARD_RESULT(s2n_wipe_record(conn));
            return S2N_SUCCESS;
        }
        POSIX_GUARD(r);
    }

    if (isSSLv2) {
        S2N_ERROR_IF(record_type != SSLv2_CLIENT_HELLO, S2N_ERR_BAD_MESSAGE);
        POSIX_GUARD(s2n_handshake_handle_sslv2(conn));
    }

    /* Now we have a record, but it could be a partial fragment of a message, or it might
     * contain several messages.
     */

    if (record_type == TLS_APPLICATION_DATA) {
        POSIX_ENSURE(conn->early_data_expected, S2N_ERR_BAD_MESSAGE);
        POSIX_GUARD_RESULT(s2n_early_data_validate_recv(conn));
        POSIX_BAIL(S2N_ERR_EARLY_DATA_BLOCKED);
    } else if (record_type == TLS_CHANGE_CIPHER_SPEC) {
        /* TLS1.3 can receive unexpected CCS messages at any point in the handshake
         * due to a peer operating in middlebox compatibility mode.
         * However, when operating in QUIC mode, S2N should not accept ANY CCS messages,
         * including these unexpected ones.*/
        if (!IS_TLS13_HANDSHAKE(conn) || s2n_connection_is_quic_enabled(conn)) {
            POSIX_ENSURE(EXPECTED_RECORD_TYPE(conn) == TLS_CHANGE_CIPHER_SPEC, S2N_ERR_BAD_MESSAGE);
            POSIX_ENSURE(!CONNECTION_IS_WRITER(conn), S2N_ERR_BAD_MESSAGE);
        }

        S2N_ERROR_IF(s2n_stuffer_data_available(&conn->in) != 1, S2N_ERR_BAD_MESSAGE);

        POSIX_GUARD(s2n_stuffer_copy(&conn->in, &conn->handshake.io, s2n_stuffer_data_available(&conn->in)));
        POSIX_GUARD(CCS_STATE(conn).handler[conn->mode] (conn));
        POSIX_GUARD(s2n_stuffer_wipe(&conn->handshake.io));

        /* We're done with the record, wipe it */
        POSIX_GUARD_RESULT(s2n_wipe_record(conn));

        /* Advance the state machine if this was an expected message */
        if (EXPECTED_RECORD_TYPE(conn) == TLS_CHANGE_CIPHER_SPEC && !CONNECTION_IS_WRITER(conn)) {
            POSIX_GUARD(s2n_advance_message(conn));
        }

        return S2N_SUCCESS;
    } else if (record_type != TLS_HANDSHAKE) {
        if (record_type == TLS_ALERT) {
            POSIX_GUARD(s2n_process_alert_fragment(conn));
        }

        /* Ignore record types that we don't support */

        /* We're done with the record, wipe it */
        POSIX_GUARD_RESULT(s2n_wipe_record(conn));
        return S2N_SUCCESS;
    }

    /* Record is a handshake message */
    S2N_ERROR_IF(s2n_stuffer_data_available(&conn->in) == 0, S2N_ERR_BAD_MESSAGE);

    while (s2n_stuffer_data_available(&conn->in)) {
        /* We're done with negotiating but we have trailing data in this record. Bail on the handshake. */
        S2N_ERROR_IF(EXPECTED_RECORD_TYPE(conn) == TLS_APPLICATION_DATA, S2N_ERR_BAD_MESSAGE);
        int r;
        POSIX_GUARD((r = s2n_read_full_handshake_message(conn, &message_type)));

        /* Do we need more data? This happens for message fragmentation */
        if (r == 1) {
            /* Break out of this inner loop, but since we're not changing the state, the
             * outer loop in s2n_handshake_io() will read another record.
             */
            POSIX_GUARD_RESULT(s2n_wipe_record(conn));
            return S2N_SUCCESS;
        }

        s2n_cert_auth_type client_cert_auth_type;
        POSIX_GUARD(s2n_connection_get_client_auth_type(conn, &client_cert_auth_type));

        /* If we're a Client, and received a ClientCertRequest message, and ClientAuth
         * is set to optional, then switch the State Machine that we're using to expect the ClientCertRequest. */
        if (conn->mode == S2N_CLIENT
                && client_cert_auth_type == S2N_CERT_AUTH_OPTIONAL
                && message_type == TLS_CERT_REQ) {
            POSIX_ENSURE(IS_FULL_HANDSHAKE(conn), S2N_ERR_HANDSHAKE_STATE);
            POSIX_GUARD_RESULT(s2n_handshake_type_set_flag(conn, CLIENT_AUTH));
        }

        /* According to rfc6066 section 8, server may choose not to send "CertificateStatus" message even if it has
         * sent "status_request" extension in the ServerHello message. */
        if (conn->mode == S2N_CLIENT
                && EXPECTED_MESSAGE_TYPE(conn) == TLS_SERVER_CERT_STATUS
                && message_type != TLS_SERVER_CERT_STATUS) {
            POSIX_GUARD_RESULT(s2n_handshake_type_unset_tls12_flag(conn, OCSP_STATUS));
        }

        /*
         *= https://tools.ietf.org/rfc/rfc5246#section-7.4
         *# The one message that is not bound by these ordering rules
         *# is the HelloRequest message, which can be sent at any time, but which
         *# SHOULD be ignored by the client if it arrives in the middle of a handshake.
         */
        if (message_type == TLS_HELLO_REQUEST) {
            POSIX_GUARD(s2n_client_hello_request_recv(conn));
            POSIX_GUARD(s2n_stuffer_wipe(&conn->handshake.io));
            continue;
        }

        POSIX_ENSURE(record_type == EXPECTED_RECORD_TYPE(conn), S2N_ERR_BAD_MESSAGE);
        POSIX_ENSURE(message_type == EXPECTED_MESSAGE_TYPE(conn), S2N_ERR_BAD_MESSAGE);
        POSIX_ENSURE(!CONNECTION_IS_WRITER(conn), S2N_ERR_BAD_MESSAGE);

        /* Call the relevant handler */
        WITH_ERROR_BLINDING(conn, POSIX_GUARD(ACTIVE_STATE(conn).handler[conn->mode] (conn)));

        /* Advance the state machine */
        POSIX_GUARD_RESULT(s2n_finish_read(conn));
    }

    /* We're done with the record, wipe it */
    POSIX_GUARD_RESULT(s2n_wipe_record(conn));
    return S2N_SUCCESS;
}

static int s2n_handle_retry_state(struct s2n_connection *conn)
{
    /* If we were blocked reading or writing a record, then the handler is waiting on
     * external data. The handler will know how to continue, so we should call the
     * handler right away. We aren't going to read more handshake data yet or proceed
     * to the next handler because the current message has not finished processing. */
    s2n_errno = S2N_ERR_OK;
    const int r = ACTIVE_STATE(conn).handler[conn->mode] (conn);

    if (r < S2N_SUCCESS && S2N_ERROR_IS_BLOCKING(s2n_errno)) {
        /* If the handler is still waiting for data, return control to the caller. */
        S2N_ERROR_PRESERVE_ERRNO();
    }

    /* Resume the handshake */
    conn->handshake.paused = false;

    if (!CONNECTION_IS_WRITER(conn)) {
        /* We're done parsing the record, reset everything */
        POSIX_GUARD(s2n_stuffer_wipe(&conn->header_in));
        POSIX_GUARD(s2n_stuffer_wipe(&conn->in));
        conn->in_status = ENCRYPTED;
    }

    if (CONNECTION_IS_WRITER(conn)) {
        POSIX_GUARD(r);

        /* If we're the writer and handler just finished, update the record header if
         * needed and let the s2n_handshake_write_io write the data to the socket */
        if (EXPECTED_RECORD_TYPE(conn) == TLS_HANDSHAKE) {
            POSIX_GUARD(s2n_handshake_finish_header(&conn->handshake.io));
        }
    } else {
        if (r < S2N_SUCCESS && conn->session_id_len) {
            s2n_try_delete_session_cache(conn);
        }
        WITH_ERROR_BLINDING(conn, POSIX_GUARD(r));

        /* The read handler processed the record successfully, we are done with this
         * record. Advance the state machine. */
        POSIX_GUARD_RESULT(s2n_finish_read(conn));
    }

    return S2N_SUCCESS;
}

int s2n_negotiate_impl(struct s2n_connection *conn, s2n_blocked_status *blocked)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(blocked);

    while (ACTIVE_STATE(conn).writer != 'B' && ACTIVE_MESSAGE(conn) != conn->handshake.end_of_messages) {
        errno = 0;
        s2n_errno = S2N_ERR_OK;

        /* Flush any pending I/O or alert messages */
        POSIX_GUARD(s2n_flush(conn, blocked));

        /* If the handshake was paused, retry the current message */
        if (conn->handshake.paused) {
            *blocked = S2N_BLOCKED_ON_APPLICATION_INPUT;
            POSIX_GUARD(s2n_handle_retry_state(conn));
        }

        if (CONNECTION_IS_WRITER(conn)) {
            *blocked = S2N_BLOCKED_ON_WRITE;
            const int write_result = s2n_handshake_write_io(conn);

            if (write_result < S2N_SUCCESS) {
                if (!S2N_ERROR_IS_BLOCKING(s2n_errno)) {
                    /* Non-retryable write error. The peer might have sent an alert. Try and read it. */
                    const int write_errno = errno;
                    const int write_s2n_errno = s2n_errno;
                    const char *write_s2n_debug_str = s2n_debug_str;

                    if (s2n_handshake_read_io(conn) < 0 && s2n_errno == S2N_ERR_ALERT) {
                        /* s2n_handshake_read_io has set s2n_errno */
                        S2N_ERROR_PRESERVE_ERRNO();
                    } else {
                        /* Let the write error take precedence if we didn't read an alert. */
                        errno = write_errno;
                        s2n_errno = write_s2n_errno;
                        s2n_debug_str = write_s2n_debug_str;
                        S2N_ERROR_PRESERVE_ERRNO();
                    }
                }

                if (s2n_errno == S2N_ERR_ASYNC_BLOCKED) {
                    *blocked = S2N_BLOCKED_ON_APPLICATION_INPUT;
                    conn->handshake.paused = true;
                } else if (s2n_errno == S2N_ERR_EARLY_DATA_BLOCKED) {
                    *blocked = S2N_BLOCKED_ON_EARLY_DATA;
                }

                S2N_ERROR_PRESERVE_ERRNO();
            }
        } else {
            *blocked = S2N_BLOCKED_ON_READ;
            const int read_result = s2n_handshake_read_io(conn);

            if (read_result < S2N_SUCCESS) {
                /* One blocking condition is waiting on the session resumption cache. */
                /* So we don't want to delete anything if we are blocked. */
                if (!S2N_ERROR_IS_BLOCKING(s2n_errno) && conn->session_id_len) {
                    s2n_try_delete_session_cache(conn);
                }

                if (s2n_errno == S2N_ERR_ASYNC_BLOCKED) {
                    *blocked = S2N_BLOCKED_ON_APPLICATION_INPUT;
                    conn->handshake.paused = true;
                } else if (s2n_errno == S2N_ERR_EARLY_DATA_BLOCKED) {
                    *blocked = S2N_BLOCKED_ON_EARLY_DATA;
                }

                S2N_ERROR_PRESERVE_ERRNO();
            }
        }

        if (ACTIVE_STATE(conn).writer == 'B') {
            /*
             * Prepare TLS1.3 resumption secret.
             * A ticket can be requested any time after the handshake ends,
             * so we need to calculate this before the handshake ends.
             */
            if (conn->actual_protocol_version >= S2N_TLS13) {
                POSIX_GUARD_RESULT(s2n_derive_resumption_master_secret(conn));
            }

            /* Send any pending post-handshake messages */
            POSIX_GUARD(s2n_post_handshake_send(conn, blocked));

            /* If the handshake has just ended, free up memory */
            POSIX_GUARD(s2n_stuffer_resize(&conn->handshake.io, 0));
        }
    }

    *blocked = S2N_NOT_BLOCKED;

    return S2N_SUCCESS;
}

int s2n_negotiate(struct s2n_connection *conn, s2n_blocked_status *blocked)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE(!conn->negotiate_in_use, S2N_ERR_REENTRANCY);
    conn->negotiate_in_use = true;
    int result = s2n_negotiate_impl(conn, blocked);
    conn->negotiate_in_use = false;
    return result;
}
