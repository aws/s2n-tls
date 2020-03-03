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

#include <string.h>
#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

#define S2N_PEM_DELIMTER_CHAR               '-'
#define S2N_PEM_DELIMITER_MIN_COUNT         1
#define S2N_PEM_DELIMITER_MAX_COUNT         64
#define S2N_PEM_BEGIN_TOKEN                 "BEGIN "
#define S2N_PEM_END_TOKEN                   "END "

#define S2N_PEM_PKCS1_RSA_PRIVATE_KEY       "RSA PRIVATE KEY"
#define S2N_PEM_PKCS1_EC_PRIVATE_KEY        "EC PRIVATE KEY"
#define S2N_PEM_PKCS8_PRIVATE_KEY           "PRIVATE KEY"
#define S2N_PEM_DH_PARAMETERS               "DH PARAMETERS"
#define S2N_PEM_EC_PARAMETERS               "EC PARAMETERS"
#define S2N_PEM_CERTIFICATE                 "CERTIFICATE"

static int s2n_stuffer_pem_read_encapsulation_line(struct s2n_stuffer *pem, const char* encap_marker, const char *keyword) {

    /* Skip any number of Chars until a "-" is reached */
    GUARD(s2n_stuffer_skip_to_char(pem, S2N_PEM_DELIMTER_CHAR));

    /* Ensure between 1 and 64 '-' chars at start of line */
    GUARD(s2n_stuffer_skip_expected_char(pem, S2N_PEM_DELIMTER_CHAR, S2N_PEM_DELIMITER_MIN_COUNT, S2N_PEM_DELIMITER_MAX_COUNT));

    /* Ensure next string in stuffer is "BEGIN " or "END " */
    GUARD(s2n_stuffer_read_expected_str(pem, encap_marker));

    /* Ensure next string is stuffer is the keyword (Eg "CERTIFICATE", "PRIVATE KEY", etc) */
    GUARD(s2n_stuffer_read_expected_str(pem, keyword));

    /* Ensure between 1 and 64 '-' chars at end of line */
    GUARD(s2n_stuffer_skip_expected_char(pem, S2N_PEM_DELIMTER_CHAR, S2N_PEM_DELIMITER_MIN_COUNT, S2N_PEM_DELIMITER_MAX_COUNT));

    /* Check for missing newline between dashes case: "-----END CERTIFICATE----------BEGIN CERTIFICATE-----" */
    if (strncmp(encap_marker, S2N_PEM_END_TOKEN, strlen(S2N_PEM_END_TOKEN)) == 0
            && s2n_stuffer_peek_check_for_str(pem, S2N_PEM_BEGIN_TOKEN)) {
        /* Rewind stuffer by 1 byte before BEGIN, so that next read will find the dash before the BEGIN */
        GUARD(s2n_stuffer_rewind_read(pem, 1));
    }

    /* Skip newlines and other whitepsace that may be after the dashes */
    GUARD(s2n_stuffer_skip_whitespace(pem));
    return 0;
}

static int s2n_stuffer_pem_read_begin(struct s2n_stuffer *pem, const char *keyword)
{
    return s2n_stuffer_pem_read_encapsulation_line(pem, S2N_PEM_BEGIN_TOKEN, keyword);
}

static int s2n_stuffer_pem_read_end(struct s2n_stuffer *pem, const char *keyword)
{
    return s2n_stuffer_pem_read_encapsulation_line(pem, S2N_PEM_END_TOKEN, keyword);
}

static int s2n_stuffer_pem_read_contents(struct s2n_stuffer *pem, struct s2n_stuffer *asn1)
{
    uint8_t base64_buf[64] = { 0 };
    struct s2n_blob base64__blob = { .data = base64_buf, .size = sizeof(base64_buf) };
    struct s2n_stuffer base64_stuffer = {0};
    GUARD(s2n_stuffer_init(&base64_stuffer, &base64__blob));

    while (1) {
        char c;
        /* Peek to see if the next char is a dash, meaning end of pem_contents */
        GUARD(s2n_stuffer_peek_char(pem, &c));
        if (c == '-') {
            break;
        } else {
            /* Else, move read pointer forward by 1 byte since we will be consuming it. */
             GUARD(s2n_stuffer_skip_read(pem, 1));
        }

         /* Skip non-base64 characters */
        if (!s2n_is_base64_char(c)) {
            continue;
        }

        /* Flush base64_stuffer to asn1 stuffer if we're out of space, and reset base64_stuffer read/write pointers */
        if (s2n_stuffer_space_remaining(&base64_stuffer) == 0) {
            GUARD(s2n_stuffer_read_base64(&base64_stuffer, asn1));
            GUARD(s2n_stuffer_rewrite(&base64_stuffer));
        }

        /* Copy next char to base64_stuffer */
        GUARD(s2n_stuffer_write_bytes(&base64_stuffer, (uint8_t *) &c, 1));

    };

    /* Flush any remaining bytes to asn1 */
    GUARD(s2n_stuffer_read_base64(&base64_stuffer, asn1));

    return 0;
}

static int s2n_stuffer_data_from_pem(struct s2n_stuffer *pem, struct s2n_stuffer *asn1, const char *keyword)
{
    GUARD(s2n_stuffer_pem_read_begin(pem, keyword));
    GUARD(s2n_stuffer_pem_read_contents(pem, asn1));
    GUARD(s2n_stuffer_pem_read_end(pem, keyword));

    return 0;
}

int s2n_stuffer_private_key_from_pem(struct s2n_stuffer *pem, struct s2n_stuffer *asn1) {
    int rc;
   
    rc = s2n_stuffer_data_from_pem(pem, asn1, S2N_PEM_PKCS1_RSA_PRIVATE_KEY);
    if (!rc) {
        return rc;
    } 
    
    s2n_stuffer_reread(pem);
    s2n_stuffer_reread(asn1);

    /* By default, OpenSSL tools always generate both "EC PARAMETERS" and "EC PRIVATE
     * KEY" PEM objects in the keyfile. Skip the first "EC PARAMETERS" object so that we're
     * compatible with OpenSSL's default output, and since "EC PARAMETERS" is
     * only needed for non-standard curves that aren't currently supported.
     */
    rc = s2n_stuffer_data_from_pem(pem, asn1, S2N_PEM_EC_PARAMETERS);
    if (rc < 0) {
        s2n_stuffer_reread(pem);
    }
    s2n_stuffer_wipe(asn1);
    
    rc = s2n_stuffer_data_from_pem(pem, asn1, S2N_PEM_PKCS1_EC_PRIVATE_KEY);
    if (!rc) {
        return rc;
    }
    
    /* If it does not match either format, try PKCS#8 */
    s2n_stuffer_reread(pem);
    s2n_stuffer_reread(asn1);
    return s2n_stuffer_data_from_pem(pem, asn1, S2N_PEM_PKCS8_PRIVATE_KEY);
}

int s2n_stuffer_certificate_from_pem(struct s2n_stuffer *pem, struct s2n_stuffer *asn1)
{
    return s2n_stuffer_data_from_pem(pem, asn1, S2N_PEM_CERTIFICATE);
}

int s2n_stuffer_dhparams_from_pem(struct s2n_stuffer *pem, struct s2n_stuffer *pkcs3)
{
    return s2n_stuffer_data_from_pem(pem, pkcs3, S2N_PEM_DH_PARAMETERS);
}
