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
#include <stdlib.h>

#include "utils/s2n_blob.h"

struct s2n_stuffer {
    /* The data for the s2n_stuffer */
    struct s2n_blob blob;

    /* Cursors to the current read/write position in the s2n_stuffer */
    uint32_t read_cursor;
    uint32_t write_cursor;

    /* The total size of the data segment */
    /* Has the stuffer been wiped? */
    unsigned int wiped:1;

    /* Was this stuffer alloc()'d ? */
    unsigned int alloced:1;

    /* Is this stuffer growable? */
    unsigned int growable:1;

    /* A growable stuffer can also be temporarily tainted */
    unsigned int tainted:1;
};

#define s2n_stuffer_data_available( s )   ((s)->write_cursor - (s)->read_cursor)
#define s2n_stuffer_space_remaining( s )  ((s)->blob.size - (s)->write_cursor)

/* Initialize and destroying stuffers */
extern int s2n_stuffer_init(struct s2n_stuffer *stuffer, struct s2n_blob *in);
extern int s2n_stuffer_alloc(struct s2n_stuffer *stuffer, const uint32_t size);
extern int s2n_stuffer_growable_alloc(struct s2n_stuffer *stuffer, const uint32_t size);
extern int s2n_stuffer_free(struct s2n_stuffer *stuffer);
extern int s2n_stuffer_resize(struct s2n_stuffer *stuffer, const uint32_t size);
extern int s2n_stuffer_reread(struct s2n_stuffer *stuffer);
extern int s2n_stuffer_rewrite(struct s2n_stuffer *stuffer);
extern int s2n_stuffer_wipe(struct s2n_stuffer *stuffer);
extern int s2n_stuffer_wipe_n(struct s2n_stuffer *stuffer, const uint32_t n);

/* Basic read and write */
extern int s2n_stuffer_read(struct s2n_stuffer *stuffer, struct s2n_blob *out);
extern int s2n_stuffer_erase_and_read(struct s2n_stuffer *stuffer, struct s2n_blob *out);
extern int s2n_stuffer_write(struct s2n_stuffer *stuffer, const struct s2n_blob *in);
extern int s2n_stuffer_read_bytes(struct s2n_stuffer *stuffer, uint8_t * out, uint32_t n);
extern int s2n_stuffer_write_bytes(struct s2n_stuffer *stuffer, const uint8_t * in, const uint32_t n);
extern int s2n_stuffer_skip_read(struct s2n_stuffer *stuffer, uint32_t n);
extern int s2n_stuffer_skip_write(struct s2n_stuffer *stuffer, const uint32_t n);

/* Raw read/write move the cursor along and give you a pointer you can
 * read/write data_len bytes from/to in-place.
 */
extern void *s2n_stuffer_raw_write(struct s2n_stuffer *stuffer, const uint32_t data_len);
extern void *s2n_stuffer_raw_read(struct s2n_stuffer *stuffer, uint32_t data_len);

/* Send/receive stuffer to/from a file descriptor */
extern int s2n_stuffer_recv_from_fd(struct s2n_stuffer *stuffer, int rfd, uint32_t len);
extern int s2n_stuffer_send_to_fd(struct s2n_stuffer *stuffer, int wfd, uint32_t len);

/* Read and write integers in network order */
extern int s2n_stuffer_read_uint8(struct s2n_stuffer *stuffer, uint8_t * u);
extern int s2n_stuffer_read_uint16(struct s2n_stuffer *stuffer, uint16_t * u);
extern int s2n_stuffer_read_uint24(struct s2n_stuffer *stuffer, uint32_t * u);
extern int s2n_stuffer_read_uint32(struct s2n_stuffer *stuffer, uint32_t * u);
extern int s2n_stuffer_read_uint64(struct s2n_stuffer *stuffer, uint64_t * u);

extern int s2n_stuffer_write_uint8(struct s2n_stuffer *stuffer, const uint8_t u);
extern int s2n_stuffer_write_uint16(struct s2n_stuffer *stuffer, const uint16_t u);
extern int s2n_stuffer_write_uint24(struct s2n_stuffer *stuffer, const uint32_t u);
extern int s2n_stuffer_write_uint32(struct s2n_stuffer *stuffer, const uint32_t u);
extern int s2n_stuffer_write_uint64(struct s2n_stuffer *stuffer, const uint64_t u);

/* Copy one stuffer to another */
extern int s2n_stuffer_copy(struct s2n_stuffer *from, struct s2n_stuffer *to, uint32_t len);

/* Read and write base64 */
extern int s2n_stuffer_read_base64(struct s2n_stuffer *stuffer, struct s2n_stuffer *out);
extern int s2n_stuffer_write_base64(struct s2n_stuffer *stuffer, struct s2n_stuffer *in);

/* Useful for text manipulation ... */
#define s2n_stuffer_write_char( stuffer, c )  s2n_stuffer_write_uint8( (stuffer), (uint8_t) (c) )
#define s2n_stuffer_read_char( stuffer, c )  s2n_stuffer_read_uint8( (stuffer), (uint8_t *) (c) )
#define s2n_stuffer_write_str( stuffer, c )  s2n_stuffer_write_bytes( (stuffer), (const uint8_t *) (c), strlen((c)) )
#define s2n_stuffer_write_text( stuffer, c, n )  s2n_stuffer_write_bytes( (stuffer), (const uint8_t *) (c), (n) )
#define s2n_stuffer_read_text( stuffer, c, n )  s2n_stuffer_read_bytes( (stuffer), (uint8_t *) (c), (n) )
extern int s2n_stuffer_peek_char(struct s2n_stuffer *stuffer, char *c);
extern int s2n_stuffer_read_token(struct s2n_stuffer *stuffer, struct s2n_stuffer *token, char delim);
extern int s2n_stuffer_skip_whitespace(struct s2n_stuffer *stuffer);
extern int s2n_stuffer_alloc_ro_from_string(struct s2n_stuffer *stuffer, const char *str);

/* Read an RSA private key from a PEM encoded stuffer to an ASN1/DER encoded one */
extern int s2n_stuffer_rsa_private_key_from_pem(struct s2n_stuffer *pem, struct s2n_stuffer *asn1);

/* Read a certificate  from a PEM encoded stuffer to an ASN1/DER encoded one */
extern int s2n_stuffer_certificate_from_pem(struct s2n_stuffer *pem, struct s2n_stuffer *asn1);

/* Read DH parameters om a PEM encoded stuffer to a PKCS3 encoded one */
extern int s2n_stuffer_dhparams_from_pem(struct s2n_stuffer *pem, struct s2n_stuffer *pkcs3);
