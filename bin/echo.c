/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <netdb.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <errno.h>

#include <s2n.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_pkey.h"

void print_s2n_error(const char *app_error)
{
    fprintf(stderr, "%s: '%s' : '%s'\n", app_error, s2n_strerror(s2n_errno, "EN"),
            s2n_strerror_debug(s2n_errno, "EN"));
}

/* Accept all RSA Certificates is unsafe and is only used in the s2n Client */
s2n_cert_validation_code accept_all_rsa_certs(struct s2n_connection *conn, uint8_t *cert_chain_in, uint32_t cert_chain_len, s2n_cert_type *cert_type_out, s2n_cert_public_key *public_key_out, void *context)
{
    uint32_t bytes_read = 0;
    uint32_t certificate_count = 0;
    while (bytes_read != cert_chain_len) {
        if (bytes_read > cert_chain_len) {
            return S2N_CERT_ERR_INVALID;
        }
        //24 Bit Cert Length
        uint32_t next_certificate_size = 0;
        next_certificate_size |= cert_chain_in[bytes_read++] << 16;
        next_certificate_size |= cert_chain_in[bytes_read++] << 8;
        next_certificate_size |= cert_chain_in[bytes_read++];


        if (next_certificate_size == 0 || next_certificate_size > (cert_chain_len - bytes_read) ) {
            return S2N_CERT_ERR_INVALID;
        }

        uint8_t *asn1_cert_data = &cert_chain_in[bytes_read];
        bytes_read += next_certificate_size;

        /* Pull the public key from the first certificate */
        if (certificate_count == 0) {
            /* Assume that the asn1cert is an RSA Cert */
            uint8_t *cert_to_parse = asn1_cert_data;
            X509 *cert = d2i_X509(NULL, (const unsigned char **)(void *)&cert_to_parse, next_certificate_size);

            if (cert == NULL) {
                return S2N_CERT_ERR_INVALID;
            }

            /* If cert parsing is successful, d2i_X509 increments *cert_to_parse to the byte following the parsed data */
            uint32_t parsed_len = cert_to_parse - asn1_cert_data;

            if (parsed_len != next_certificate_size) {
                X509_free(cert);
                return S2N_CERT_ERR_INVALID;
            }

            EVP_PKEY *public_key = X509_get_pubkey(cert);
            X509_free(cert);

            if (public_key == NULL) {
                return S2N_CERT_ERR_INVALID;
            }

            if (EVP_PKEY_base_id(public_key) != EVP_PKEY_RSA) {
                EVP_PKEY_free(public_key);
                return S2N_CERT_ERR_TYPE_UNSUPPORTED;
            }

            RSA *openssl_rsa;
            openssl_rsa = EVP_PKEY_get1_RSA(public_key);
            EVP_PKEY_free(public_key);
            if (openssl_rsa == NULL) {
                return S2N_CERT_ERR_INVALID;
            }

            if (s2n_cert_public_key_set_rsa_from_openssl(public_key_out, openssl_rsa) < 0) {
                return S2N_CERT_ERR_INVALID;
            }

            *cert_type_out = S2N_CERT_TYPE_RSA_SIGN;                            
        }

        certificate_count++;
    }

    // Allow Cert Chains of at least length 1 for Self-Signed Certs
    if (certificate_count == 0) {
        return S2N_CERT_ERR_INVALID;
    }

    return 0;
}

int negotiate(struct s2n_connection *conn)
{
    s2n_blocked_status blocked;
    do {
        if (s2n_negotiate(conn, &blocked) < 0) {
            fprintf(stderr, "Failed to negotiate: '%s' %d\n", s2n_strerror(s2n_errno, "EN"), s2n_connection_get_alert(conn));
            return -1;
        }
    } while (blocked);

    /* Now that we've negotiated, print some parameters */
    int client_hello_version;
    int client_protocol_version;
    int server_protocol_version;
    int actual_protocol_version;

    if ((client_hello_version = s2n_connection_get_client_hello_version(conn)) < 0) {
        fprintf(stderr, "Could not get client hello version\n");
        return -1;
    }
    if ((client_protocol_version = s2n_connection_get_client_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get client protocol version\n");
        return -1;
    }
    if ((server_protocol_version = s2n_connection_get_server_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get server protocol version\n");
        return -1;
    }
    if ((actual_protocol_version = s2n_connection_get_actual_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get actual protocol version\n");
        return -1;
    }
    printf("Client hello version: %d\n", client_hello_version);
    printf("Client protocol version: %d\n", client_protocol_version);
    printf("Server protocol version: %d\n", server_protocol_version);
    printf("Actual protocol version: %d\n", actual_protocol_version);

    if (s2n_get_server_name(conn)) {
        printf("Server name: %s\n", s2n_get_server_name(conn));
    }

    if (s2n_get_application_protocol(conn)) {
        printf("Application protocol: %s\n", s2n_get_application_protocol(conn));
    }

    printf("Curve: %s\n", s2n_connection_get_curve(conn));

    uint32_t length;
    const uint8_t *status = s2n_connection_get_ocsp_response(conn, &length);
    if (status && length > 0) {
        fprintf(stderr, "OCSP response received, length %u\n", length);
    }

    printf("Cipher negotiated: %s\n", s2n_connection_get_cipher(conn));

    return 0;
}

int echo(struct s2n_connection *conn, int sockfd)
{
    struct pollfd readers[2];

    readers[0].fd = sockfd;
    readers[0].events = POLLIN;
    readers[1].fd = STDIN_FILENO;
    readers[1].events = POLLIN;

    /* Act as a simple proxy between stdin and the SSL connection */
    int p;
    s2n_blocked_status blocked;
  POLL:
    while ((p = poll(readers, 2, -1)) > 0) {
        char buffer[10240];
        int bytes_read, bytes_written;

        if (readers[0].revents & POLLIN) {
            do {
                bytes_read = s2n_recv(conn, buffer, 10240, &blocked);
                if (bytes_read == 0) {
                    /* Connection has been closed */
                    s2n_connection_wipe(conn);
                    return 0;
                }
                if (bytes_read < 0) {
                    fprintf(stderr, "Error reading from connection: '%s' %d\n", s2n_strerror(s2n_errno, "EN"), s2n_connection_get_alert(conn));
                    exit(1);
                }
                bytes_written = write(STDOUT_FILENO, buffer, bytes_read);
                if (bytes_written <= 0) {
                    fprintf(stderr, "Error writing to stdout\n");
                    exit(1);
                }
            } while (blocked);
        }
        if (readers[1].revents & POLLIN) {
            int bytes_available;
            if (ioctl(STDIN_FILENO, FIONREAD, &bytes_available) < 0) {
                bytes_available = 1;
            }
            if (bytes_available > sizeof(buffer)) {
                bytes_available = sizeof(buffer);
            }

            /* Read as many bytes as we think we can */
          READ:
            bytes_read = read(STDIN_FILENO, buffer, bytes_available);
            if (bytes_read < 0) {
                if (errno == EINTR) {
                    goto READ;
                }
                fprintf(stderr, "Error reading from stdin\n");
                exit(1);
            }
            if (bytes_read == 0) {
                /* Exit on EOF */
                return 0;
            }

            char *buf_ptr = buffer;
            do {
                bytes_written = s2n_send(conn, buf_ptr, bytes_available, &blocked);
                if (bytes_written < 0) {
                    fprintf(stderr, "Error writing to connection: '%s'\n", s2n_strerror(s2n_errno, "EN"));
                    exit(1);
                }

                bytes_available -= bytes_written;
                buf_ptr += bytes_written;
            } while (bytes_available || blocked);
        }
    }
    if (p < 0 && errno == EINTR) {
        goto POLL;
    }

    return 0;
}
