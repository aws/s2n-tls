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

#include <strings.h>

#include "error/s2n_errno.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_config.h"

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

/* s2n's list of cipher suites, in order of preference, as of 2014-06-01 */
uint8_t wire_format_20140601[] =
    { TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_RC4_128_SHA, TLS_RSA_WITH_RC4_128_MD5
};
struct s2n_cipher_preferences cipher_preferences_20140601 = {
    .count = sizeof(wire_format_20140601) / S2N_TLS_CIPHER_SUITE_LEN,
    .wire_format = wire_format_20140601,
    .minimum_protocol_version = S2N_SSLv3
};

/* Disable SSLv3 due to POODLE */
struct s2n_cipher_preferences cipher_preferences_20141001 = {
    .count = sizeof(wire_format_20140601) / S2N_TLS_CIPHER_SUITE_LEN,
    .wire_format = wire_format_20140601,
    .minimum_protocol_version = S2N_TLS10
};

/* Disable RC4 */
uint8_t wire_format_20150202[] =
    { TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA
};
struct s2n_cipher_preferences cipher_preferences_20150202 = {
    .count = sizeof(wire_format_20150202) / S2N_TLS_CIPHER_SUITE_LEN,
    .wire_format = wire_format_20150202,
    .minimum_protocol_version = S2N_TLS10
};

/* Support AES-GCM modes */
uint8_t wire_format_20150214[] =
    { TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA
};
struct s2n_cipher_preferences cipher_preferences_20150214 = {
    .count = sizeof(wire_format_20150214) / S2N_TLS_CIPHER_SUITE_LEN,
    .wire_format = wire_format_20150214,
    .minimum_protocol_version = S2N_TLS10
};

struct {
    const char * version;
    struct s2n_cipher_preferences * preferences;
} selection[] = {
    { "default", &cipher_preferences_20150214 },
    { "20140601", &cipher_preferences_20140601 },
    { "20141001", &cipher_preferences_20141001 },
    { "20150202", &cipher_preferences_20150202 },
    { "20150214", &cipher_preferences_20150214 },
    { NULL, NULL }
};

struct s2n_config s2n_default_config = {
    .cert_and_key_pairs = NULL,
    .cipher_preferences = &cipher_preferences_20150214
};

struct s2n_config *s2n_config_new()
{
    struct s2n_blob allocator;
    struct s2n_config *new_config;

    GUARD_PTR(s2n_alloc(&allocator, sizeof(struct s2n_config)));

    new_config = (struct s2n_config *)(void *)allocator.data;
    new_config->cert_and_key_pairs = NULL;
    new_config->dhparams = NULL;
    new_config->application_protocols.data = NULL;
    new_config->application_protocols.size = 0;

    GUARD_PTR(s2n_config_set_cipher_preferences(new_config, "default"));

    return new_config;
}

int s2n_config_free_cert_chain_and_key(struct s2n_config *config)
{
    struct s2n_blob b = {
        .data = (uint8_t *) config->cert_and_key_pairs,
        .size = sizeof(struct s2n_cert_chain_and_key)
    };

    /* If there were cert and key pairs set, walk the chain and free the certs */
    if (config->cert_and_key_pairs) {
        struct s2n_cert_chain *node = config->cert_and_key_pairs->head;
        while (node) {
            struct s2n_blob n = {
                .data = (uint8_t *)node,
                .size = sizeof(struct s2n_cert_chain)
            };
            /* Free the cert */
            GUARD(s2n_free(&node->cert));
            /* Advance to next */
            node = node->next;
            /* Free the node */
            GUARD(s2n_free(&n));
        }
        GUARD(s2n_rsa_private_key_free(&config->cert_and_key_pairs->private_key));
    }

    GUARD(s2n_free(&b));
    return 0;
}

int s2n_config_free_dhparams(struct s2n_config *config)
{
    struct s2n_blob b = {
        .data = (uint8_t *) config->dhparams,
        .size = sizeof(struct s2n_dh_params)
    };

    if (config->dhparams) {
        GUARD(s2n_dh_params_free(config->dhparams));
    }

    GUARD(s2n_free(&b));
    return 0;
}

int s2n_config_free(struct s2n_config *config)
{
    struct s2n_blob b = {.data = (uint8_t *) config,.size = sizeof(struct s2n_config) };

    GUARD(s2n_config_free_cert_chain_and_key(config));
    GUARD(s2n_config_free_dhparams(config));
    GUARD(s2n_free(&config->application_protocols));

    GUARD(s2n_free(&b));
    return 0;
}

int s2n_config_set_cipher_preferences(struct s2n_config *config, const char *version)
{
    for (int i = 0; selection[i].version != NULL; i++) {
        if (!strcasecmp(version, selection[i].version)) {
            config->cipher_preferences = selection[i].preferences;
            return 0;
        }
    }

    s2n_errno = S2N_ERR_INVALID_CIPHER_PREFERENCES;
    return -1;
}

int s2n_config_set_protocol_preferences(struct s2n_config *config, const char **protocols)
{
    struct s2n_stuffer protocol_stuffer;

    GUARD(s2n_free(&config->application_protocols));

    if (protocols == NULL) {
        /* NULL value indicates no prference, so nothing to do */
        return 0;
    }

    GUARD(s2n_stuffer_growable_alloc(&protocol_stuffer, 256));
    for (int i = 0; protocols[i] != NULL; i++) {
        size_t length = strlen(protocols[i]);
        uint8_t protocol[255];

        if (length > 255 || (s2n_stuffer_data_available(&protocol_stuffer) + length + 1) > 65535) {
            return S2N_ERR_APPLICATION_PROTOCOL_TOO_LONG;
        }
        memcpy_check(protocol, protocols[i], length);
        GUARD(s2n_stuffer_write_uint8(&protocol_stuffer, length));
        GUARD(s2n_stuffer_write_bytes(&protocol_stuffer, protocol, length));
    }

    uint32_t size = s2n_stuffer_data_available(&protocol_stuffer);
    /* config->application_protocols blob now owns this data */
    config->application_protocols.size = size;
    config->application_protocols.data = s2n_stuffer_raw_read(&protocol_stuffer, size);
    notnull_check(config->application_protocols.data);

    return 0;
}

int s2n_config_add_cert_chain_and_key(struct s2n_config *config, char *cert_chain_pem, char *private_key_pem)
{
    struct s2n_stuffer chain_in_stuffer, cert_out_stuffer, key_in_stuffer, key_out_stuffer;
    struct s2n_blob key_blob;
    struct s2n_blob mem;

    /* Allocate the memory for the chain and key struct */
    GUARD(s2n_alloc(&mem, sizeof(struct s2n_cert_chain_and_key)));
    config->cert_and_key_pairs = (struct s2n_cert_chain_and_key *)(void *)mem.data;

    /* Put the private key pem in a stuffer */
    GUARD(s2n_stuffer_alloc_ro_from_string(&key_in_stuffer, private_key_pem));
    GUARD(s2n_stuffer_growable_alloc(&key_out_stuffer, strlen(private_key_pem)));

    /* Convert pem to asn1 and asn1 to the private key */
    GUARD(s2n_stuffer_rsa_private_key_from_pem(&key_in_stuffer, &key_out_stuffer));
    GUARD(s2n_stuffer_free(&key_in_stuffer));
    key_blob.size = s2n_stuffer_data_available(&key_out_stuffer);
    key_blob.data = s2n_stuffer_raw_read(&key_out_stuffer, key_blob.size);
    notnull_check(key_blob.data);
    GUARD(s2n_asn1der_to_rsa_private_key(&config->cert_and_key_pairs->private_key, &key_blob));
    GUARD(s2n_stuffer_free(&key_out_stuffer));

    /* Turn the chain into a stuffer */
    GUARD(s2n_stuffer_alloc_ro_from_string(&chain_in_stuffer, cert_chain_pem));
    GUARD(s2n_stuffer_growable_alloc(&cert_out_stuffer, 2048));

    struct s2n_cert_chain **insert = &config->cert_and_key_pairs->head;
    uint32_t chain_size = 0;
    do {
        struct s2n_cert_chain *new_node;

        if (s2n_stuffer_certificate_from_pem(&chain_in_stuffer, &cert_out_stuffer) < 0) {
            if (chain_size == 0) {
                S2N_ERROR(S2N_ERR_NO_CERTIFICATE_IN_PEM);
            }
            break;
        }

        GUARD(s2n_alloc(&mem, sizeof(struct s2n_cert_chain)));
        new_node = (struct s2n_cert_chain *)(void *)mem.data;

        GUARD(s2n_alloc(&new_node->cert, s2n_stuffer_data_available(&cert_out_stuffer)));
        GUARD(s2n_stuffer_read(&cert_out_stuffer, &new_node->cert));

        /* Additional 3 bytes for the length field in the protocol */
        chain_size += new_node->cert.size + 3;
        new_node->next = NULL;
        *insert = new_node;
        insert = &new_node->next;
    } while (s2n_stuffer_data_available(&chain_in_stuffer));

    GUARD(s2n_stuffer_free(&chain_in_stuffer));
    GUARD(s2n_stuffer_free(&cert_out_stuffer));

    config->cert_and_key_pairs->chain_size = chain_size;

    return 0;
}

int s2n_config_add_dhparams(struct s2n_config *config, char *dhparams_pem)
{
    struct s2n_stuffer dhparams_in_stuffer, dhparams_out_stuffer;
    struct s2n_blob dhparams_blob;
    struct s2n_blob mem;

    /* Allocate the memory for the chain and key struct */
    GUARD(s2n_alloc(&mem, sizeof(struct s2n_dh_params)));
    config->dhparams = (struct s2n_dh_params *)(void *)mem.data;

    GUARD(s2n_stuffer_alloc_ro_from_string(&dhparams_in_stuffer, dhparams_pem));
    GUARD(s2n_stuffer_growable_alloc(&dhparams_out_stuffer, strlen(dhparams_pem)));

    /* Convert pem to asn1 and asn1 to the private key */
    GUARD(s2n_stuffer_dhparams_from_pem(&dhparams_in_stuffer, &dhparams_out_stuffer));

    GUARD(s2n_stuffer_free(&dhparams_in_stuffer));

    dhparams_blob.size = s2n_stuffer_data_available(&dhparams_out_stuffer);
    dhparams_blob.data = s2n_stuffer_raw_read(&dhparams_out_stuffer, dhparams_blob.size);
    notnull_check(dhparams_blob.data);

    GUARD(s2n_pkcs3_to_dh_params(config->dhparams, &dhparams_blob));

    GUARD(s2n_free(&dhparams_blob));

    return 0;
}
