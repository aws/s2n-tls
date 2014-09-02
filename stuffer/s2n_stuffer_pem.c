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

#include <string.h>

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

#define S2N_PEM_LINE_LENGTH 64
#define S2N_PEM_LINE         "-----"
#define S2N_PEM_BEGIN_TOKEN (S2N_PEM_LINE "BEGIN ")
#define S2N_PEM_END_TOKEN   (S2N_PEM_LINE "END ")

static int s2n_stuffer_data_from_pem(struct s2n_stuffer *pem, struct s2n_stuffer *asn1, const char *keyword, const char **err)
{
    uint8_t linepad[S2N_PEM_LINE_LENGTH + 1];
    struct s2n_blob line_blob = {.data = linepad,.size = S2N_PEM_LINE_LENGTH + 1 };
    struct s2n_stuffer line;
    uint8_t *field;

    GUARD(s2n_stuffer_init(&line, &line_blob, err));
    GUARD(s2n_stuffer_read_token(pem, &line, '\n', err));

    /* Check that the line matches the header */
    field = s2n_stuffer_raw_read(&line, sizeof(S2N_PEM_BEGIN_TOKEN) - 1, err);
    notnull_check(field);
    if (memcmp(field, S2N_PEM_BEGIN_TOKEN, sizeof(S2N_PEM_BEGIN_TOKEN) - 1)) {
        *err = "Error parsing non-PEM data";
        return -1;
    }

    field = s2n_stuffer_raw_read(&line, strlen(keyword), err);
    notnull_check(field);
    if (memcmp(field, keyword, strlen(keyword))) {
        *err = "Error parsing non-PEM data";
        return -1;
    }

    field = s2n_stuffer_raw_read(&line, sizeof(S2N_PEM_LINE) - 1, err);
    notnull_check(field);
    if (memcmp(field, S2N_PEM_LINE, sizeof(S2N_PEM_LINE) - 1)) {
        *err = "Error parsing non-PEM data";
        return -1;
    }

    /* Get the actual base64 data */
    do {
        GUARD(s2n_stuffer_rewrite(&line, err));
        GUARD(s2n_stuffer_read_token(pem, &line, '\n', err));

        char c;
        GUARD(s2n_stuffer_peek_char(&line, &c, err));
        if (c == '-') {
            GUARD(s2n_stuffer_reread(&line, err));
            break;
        }

        if (s2n_stuffer_read_base64(&line, asn1, err) < 0) {
            GUARD(s2n_stuffer_reread(&line, err));
            break;
        }

    } while (1);

    /* Check that the line matches the trailer */
    field = s2n_stuffer_raw_read(&line, sizeof(S2N_PEM_END_TOKEN) - 1, err);
    notnull_check(field);
    if (memcmp(field, S2N_PEM_END_TOKEN, sizeof(S2N_PEM_END_TOKEN) - 1)) {
        *err = "Error parsing non-PEM data 1";
        return -1;
    }

    field = s2n_stuffer_raw_read(&line, strlen(keyword), err);
    notnull_check(field);
    if (memcmp(field, keyword, strlen(keyword))) {
        *err = "Error parsing non-PEM data 2";
        return -1;
    }

    field = s2n_stuffer_raw_read(&line, sizeof(S2N_PEM_LINE) - 1, err);
    notnull_check(field);
    if (memcmp(field, S2N_PEM_LINE, sizeof(S2N_PEM_LINE) - 1)) {
        *err = "Error parsing non-PEM data 3";
        return -1;
    }

    return 0;
}

int s2n_stuffer_rsa_private_key_from_pem(struct s2n_stuffer *pem, struct s2n_stuffer *asn1, const char **err)
{
    return s2n_stuffer_data_from_pem(pem, asn1, "RSA PRIVATE KEY", err);
}

int s2n_stuffer_certificate_from_pem(struct s2n_stuffer *pem, struct s2n_stuffer *asn1, const char **err)
{
    return s2n_stuffer_data_from_pem(pem, asn1, "CERTIFICATE", err);
}

int s2n_stuffer_dhparams_from_pem(struct s2n_stuffer *pem, struct s2n_stuffer *pkcs3, const char **err)
{
    return s2n_stuffer_data_from_pem(pem, pkcs3, "DH PARAMETERS", err);
}
