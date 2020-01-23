/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_x509_validator.h"
#include "tls/extensions/s2n_server_certificate_status.h"
#include "utils/s2n_safety.h"

int s2n_server_certificate_status_parse(struct s2n_connection *conn, struct s2n_blob *status)
{
    GUARD(s2n_alloc(&conn->status_response, status->size));
    memcpy_check(conn->status_response.data, status->data, status->size);
    conn->status_response.size = status->size;

    return s2n_x509_validator_validate_cert_stapled_ocsp_response(&conn->x509_validator, conn,
                                                                      conn->status_response.data, conn->status_response.size);
}
