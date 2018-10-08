/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#pragma once

#include <stdint.h>

#include "tls/s2n_connection.h"

extern uint8_t s2n_highest_protocol_version;
extern uint8_t s2n_unknown_protocol_version;

extern int s2n_flush(struct s2n_connection *conn, s2n_blocked_status * more);
extern int s2n_client_hello_send(struct s2n_connection *conn);
extern int s2n_client_hello_recv(struct s2n_connection *conn);
extern int s2n_client_hello_recv_new(struct s2n_connection *conn);
extern int s2n_sslv2_client_hello_recv(struct s2n_connection *conn);
extern int s2n_server_hello_send(struct s2n_connection *conn);
extern int s2n_server_hello_recv(struct s2n_connection *conn);
extern int s2n_server_cert_send(struct s2n_connection *conn);
extern int s2n_server_cert_recv(struct s2n_connection *conn);
extern int s2n_server_status_send(struct s2n_connection *conn);
extern int s2n_server_status_recv(struct s2n_connection *conn);
extern int s2n_server_key_send(struct s2n_connection *conn);
extern int s2n_server_key_recv(struct s2n_connection *conn);
extern int s2n_client_cert_req_recv(struct s2n_connection *conn);
extern int s2n_client_cert_req_send(struct s2n_connection *conn);
extern int s2n_server_done_send(struct s2n_connection *conn);
extern int s2n_server_done_recv(struct s2n_connection *conn);
extern int s2n_client_cert_recv(struct s2n_connection *conn);
extern int s2n_client_cert_send(struct s2n_connection *conn);
extern int s2n_client_key_send(struct s2n_connection *conn);
extern int s2n_client_key_recv(struct s2n_connection *conn);
extern int s2n_client_cert_verify_recv(struct s2n_connection *conn);
extern int s2n_client_cert_verify_send(struct s2n_connection *conn);
extern int s2n_client_ccs_send(struct s2n_connection *conn);
extern int s2n_client_ccs_recv(struct s2n_connection *conn);
extern int s2n_server_nst_send(struct s2n_connection *conn);
extern int s2n_server_nst_recv(struct s2n_connection *conn);
extern int s2n_server_ccs_send(struct s2n_connection *conn);
extern int s2n_server_ccs_recv(struct s2n_connection *conn);
extern int s2n_client_finished_send(struct s2n_connection *conn);
extern int s2n_client_finished_recv(struct s2n_connection *conn);
extern int s2n_server_finished_send(struct s2n_connection *conn);
extern int s2n_server_finished_recv(struct s2n_connection *conn);
extern int s2n_server_session_lookup(struct s2n_connection *conn);
extern int s2n_handshake_write_header(struct s2n_connection *conn, uint8_t message_type);
extern int s2n_handshake_finish_header(struct s2n_connection *conn);
extern int s2n_handshake_parse_header(struct s2n_connection *conn, uint8_t * message_type, uint32_t * length);
extern int s2n_read_full_record(struct s2n_connection *conn, uint8_t * record_type, int *isSSLv2);
extern int s2n_recv_close_notify(struct s2n_connection *conn, s2n_blocked_status * blocked);
extern int s2n_client_extensions_send(struct s2n_connection *conn, struct s2n_stuffer *out);
extern int s2n_client_extensions_recv(struct s2n_connection *conn, struct s2n_array *parsed_extensions);
extern int s2n_server_extensions_send(struct s2n_connection *conn, struct s2n_stuffer *out);
extern int s2n_server_extensions_recv(struct s2n_connection *conn, struct s2n_blob *extensions);

extern uint16_t mfl_code_to_length[5];

#define s2n_server_can_send_ocsp(conn) ((conn)->status_type == S2N_STATUS_REQUEST_OCSP && \
        (conn)->config->cert_and_key_pairs && \
        (conn)->config->cert_and_key_pairs->ocsp_status.size > 0)

#define s2n_server_sent_ocsp(conn) ((conn)->mode == S2N_CLIENT && \
        (conn)->status_type == S2N_STATUS_REQUEST_OCSP)

#define s2n_server_can_send_sct_list(conn) ((conn)->ct_level_requested == S2N_CT_SUPPORT_REQUEST && \
        (conn)->config->cert_and_key_pairs && \
        (conn)->config->cert_and_key_pairs->sct_list.size > 0)

#define s2n_server_sending_nst(conn) ((conn)->config->use_tickets && \
        (conn)->session_ticket_status == S2N_NEW_TICKET)
