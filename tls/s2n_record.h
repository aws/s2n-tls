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

#include "s2n_connection.h"

extern int s2n_record_max_write_payload_size(struct s2n_connection *conn);
extern int s2n_record_write(struct s2n_connection *conn, uint8_t content_type, struct s2n_blob *in);
extern int s2n_record_parse(struct s2n_connection *conn);
extern int s2n_record_header_parse(struct s2n_connection *conn, uint8_t * content_type, uint16_t * fragment_length);
extern int s2n_sslv2_record_header_parse(struct s2n_connection *conn, uint8_t * record_type, uint8_t * client_protocol_version, uint16_t * fragment_length);
extern int s2n_verify_cbc(struct s2n_connection *conn, struct s2n_hmac_state *hmac, struct s2n_blob *decrypted);
extern int s2n_aead_aad_init(const struct s2n_connection *conn, uint8_t * sequence_number, uint8_t content_type, uint16_t record_length, struct s2n_stuffer *ad);
