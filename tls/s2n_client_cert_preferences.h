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

#include <s2n.h>

/* Only Support Certificates signed using RSA. */
static uint8_t s2n_cert_type_preference_list[] = {
    S2N_CERT_TYPE_RSA_SIGN
};

int s2n_recv_client_cert_preferences(struct s2n_stuffer *in, s2n_cert_type *chosen_cert_type);
int s2n_choose_preferred_client_cert_type(struct s2n_stuffer *in, int certs_available, uint8_t *cert_types, s2n_cert_type *chosen_cert_type);
