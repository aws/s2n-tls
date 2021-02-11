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

#pragma once

#include <s2n.h>

#include "tls/s2n_crypto_constants.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

struct s2n_early_data_config {
    uint32_t max_early_data;
    uint8_t protocol_version;
    uint8_t cipher_suite_iana[S2N_TLS_CIPHER_SUITE_LEN];
    struct s2n_blob application_protocol;
    struct s2n_blob context;
};
S2N_CLEANUP_RESULT s2n_early_data_config_free(struct s2n_early_data_config *config);

/* Public Interface -- will be made visible and moved to s2n.h when the 0RTT feature is released */

struct s2n_psk;
int s2n_psk_configure_early_data(struct s2n_psk *psk, uint32_t max_early_data,
        uint8_t cipher_suite_first_byte, uint8_t cipher_suite_second_byte);
int s2n_psk_set_application_protocol(struct s2n_psk *psk, const uint8_t *application_protocol, uint8_t size);
int s2n_psk_set_context(struct s2n_psk *psk, const uint8_t *context, uint16_t size);
