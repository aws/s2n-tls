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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "error/s2n_errno.h"

#include <s2n.h>
#include "utils/s2n_map.h"
#include "utils/s2n_safety.h"

__thread int s2n_errno;
__thread const char *s2n_debug_str;

static const char *no_such_language = "Language is not supported for error translation";
static const char *no_such_error = "Internal s2n error";

struct s2n_error_translation {
    int errno_value;
    const char *error_name;
    const char *str;
};

#define ERROR_STRING(x, y) { (x) , (#x), (y) },

struct s2n_error_translation S2N_ERROR_EN[] = {
    ERROR_STRING(S2N_ERR_OK, "no error")
    ERROR_STRING(S2N_ERR_IO, "underlying I/O operation failed, check system errno")
    ERROR_STRING(S2N_ERR_BLOCKED, "underlying I/O operation would block")
    ERROR_STRING(S2N_ERR_KEY_INIT, "error initializing encryption key")
    ERROR_STRING(S2N_ERR_ENCRYPT, "error encrypting data")
    ERROR_STRING(S2N_ERR_DECRYPT, "error decrypting data")
    ERROR_STRING(S2N_ERR_MADVISE, "error calling madvise")
    ERROR_STRING(S2N_ERR_ALLOC, "error allocating memory")
    ERROR_STRING(S2N_ERR_MLOCK, "error calling mlock (Did you run prlimit?)")
    ERROR_STRING(S2N_ERR_MUNLOCK, "error calling munlock")
    ERROR_STRING(S2N_ERR_FSTAT, "error calling fstat")
    ERROR_STRING(S2N_ERR_OPEN, "error calling open")
    ERROR_STRING(S2N_ERR_MMAP, "error calling mmap")
    ERROR_STRING(S2N_ERR_ATEXIT, "error calling atexit")
    ERROR_STRING(S2N_ERR_NULL, "NULL pointer encountered")
    ERROR_STRING(S2N_ERR_CLOSED, "connection is closed")
    ERROR_STRING(S2N_ERR_SAFETY, "a safety check failed")
    ERROR_STRING(S2N_ERR_NOT_INITIALIZED, "s2n not initialized")
    ERROR_STRING(S2N_ERR_RANDOM_UNINITIALIZED, "s2n entropy not initialized")
    ERROR_STRING(S2N_ERR_OPEN_RANDOM, "error opening urandom")
    ERROR_STRING(S2N_ERR_RESIZE_STATIC_STUFFER, "cannot resize a static stuffer")
    ERROR_STRING(S2N_ERR_RESIZE_TAINTED_STUFFER, "cannot resize a tainted stuffer")
    ERROR_STRING(S2N_ERR_STUFFER_OUT_OF_DATA, "stuffer is out of data")
    ERROR_STRING(S2N_ERR_STUFFER_IS_FULL, "stuffer is full")
    ERROR_STRING(S2N_ERR_STUFFER_NOT_FOUND, "stuffer expected bytes were not found")
    ERROR_STRING(S2N_ERR_STUFFER_HAS_UNPROCESSED_DATA, "stuffer has unprocessed data")
    ERROR_STRING(S2N_ERR_INVALID_BASE64, "invalid base64 encountered")
    ERROR_STRING(S2N_ERR_INVALID_PEM, "invalid PEM encountered")
    ERROR_STRING(S2N_ERR_DH_COPYING_PARAMETERS, "error copying Diffie-Hellman parameters")
    ERROR_STRING(S2N_ERR_DH_COPYING_PUBLIC_KEY, "error copying Diffie-Hellman public key")
    ERROR_STRING(S2N_ERR_DH_GENERATING_PARAMETERS, "error generating Diffie-Hellman parameters")
    ERROR_STRING(S2N_ERR_DH_PARAMS_CREATE, "error creating Diffie-Hellman parameters")
    ERROR_STRING(S2N_ERR_DH_SERIALIZING, "error serializing Diffie-Hellman parameters")
    ERROR_STRING(S2N_ERR_DH_SHARED_SECRET, "error computing Diffie-Hellman shared secret")
    ERROR_STRING(S2N_ERR_DH_WRITING_PUBLIC_KEY, "error writing Diffie-Hellman public key")
    ERROR_STRING(S2N_ERR_DH_FAILED_SIGNING, "error signing Diffie-Hellman values")
    ERROR_STRING(S2N_ERR_DH_TOO_SMALL, "Diffie-Hellman parameters are too small")
    ERROR_STRING(S2N_ERR_DH_PARAMETER_CHECK, "Diffie-Hellman parameter check failed")
    ERROR_STRING(S2N_ERR_INVALID_PKCS3, "invalid PKCS3 encountered")
    ERROR_STRING(S2N_ERR_HASH_DIGEST_FAILED, "failed to create hash digest")
    ERROR_STRING(S2N_ERR_HASH_INIT_FAILED, "error initializing hash")
    ERROR_STRING(S2N_ERR_HASH_INVALID_ALGORITHM, "invalid hash algorithm")
    ERROR_STRING(S2N_ERR_HASH_UPDATE_FAILED, "error updating hash")
    ERROR_STRING(S2N_ERR_HASH_COPY_FAILED, "error copying hash")
    ERROR_STRING(S2N_ERR_HASH_WIPE_FAILED, "error wiping hash")
    ERROR_STRING(S2N_ERR_HASH_NOT_READY, "hash not in a valid state for the attempted operation")
    ERROR_STRING(S2N_ERR_ALLOW_MD5_FOR_FIPS_FAILED, "error allowing MD5 to be used when in FIPS mode")
    ERROR_STRING(S2N_ERR_HMAC_INVALID_ALGORITHM, "invalid HMAC algorithm")
    ERROR_STRING(S2N_ERR_HKDF_OUTPUT_SIZE, "invalid HKDF output size")
    ERROR_STRING(S2N_ERR_PRF_INVALID_ALGORITHM, "invalid prf hash algorithm")
    ERROR_STRING(S2N_ERR_PRF_INVALID_SEED, "invalid prf seeds provided")
    ERROR_STRING(S2N_ERR_P_HASH_INVALID_ALGORITHM, "invalid p_hash algorithm")
    ERROR_STRING(S2N_ERR_P_HASH_INIT_FAILED, "error initializing p_hash")
    ERROR_STRING(S2N_ERR_P_HASH_UPDATE_FAILED, "error updating p_hash")
    ERROR_STRING(S2N_ERR_P_HASH_FINAL_FAILED, "error creating p_hash digest")
    ERROR_STRING(S2N_ERR_P_HASH_WIPE_FAILED, "error wiping p_hash")
    ERROR_STRING(S2N_ERR_SIZE_MISMATCH, "size mismatch")
    ERROR_STRING(S2N_ERR_DECODE_CERTIFICATE, "error decoding certificate")
    ERROR_STRING(S2N_ERR_DECODE_PRIVATE_KEY, "error decoding private key")
    ERROR_STRING(S2N_ERR_KEY_MISMATCH, "public and private key do not match")
    ERROR_STRING(S2N_ERR_NOMEM, "no memory")
    ERROR_STRING(S2N_ERR_SIGN, "error signing data")
    ERROR_STRING(S2N_ERR_VERIFY_SIGNATURE, "error verifying signature")
    ERROR_STRING(S2N_ERR_ALERT_PRESENT, "TLS alert is already pending")
    ERROR_STRING(S2N_ERR_ALERT, "TLS alert received")
    ERROR_STRING(S2N_ERR_CBC_VERIFY, "Failed CBC verification")
    ERROR_STRING(S2N_ERR_CIPHER_NOT_SUPPORTED, "Cipher is not supported")
    ERROR_STRING(S2N_ERR_BAD_MESSAGE, "Bad message encountered")
    ERROR_STRING(S2N_ERR_INVALID_SIGNATURE_ALGORITHM, "Invalid signature algorithm")
    ERROR_STRING(S2N_ERR_NO_CERTIFICATE_IN_PEM, "No certificate in PEM")
    ERROR_STRING(S2N_ERR_NO_ALERT, "No Alert present")
    ERROR_STRING(S2N_ERR_CLIENT_MODE, "operation not allowed in client mode")
    ERROR_STRING(S2N_ERR_SERVER_NAME_TOO_LONG, "server name is too long")
    ERROR_STRING(S2N_ERR_NUM_DEFAULT_CERTIFICATES, "exceeded max default certificates or provided no default")
    ERROR_STRING(S2N_ERR_MULTIPLE_DEFAULT_CERTIFICATES_PER_AUTH_TYPE, "setting multiple default certificates per auth type is not allowed")
    ERROR_STRING(S2N_ERR_CLIENT_MODE_DISABLED, "client connections not allowed")
    ERROR_STRING(S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_FIPS_MODE, "Client Auth is not supported when in FIPS mode")
    ERROR_STRING(S2N_ERR_HANDSHAKE_STATE, "Invalid handshake state encountered")
    ERROR_STRING(S2N_ERR_FALLBACK_DETECTED, "TLS fallback detected")
    ERROR_STRING(S2N_ERR_INVALID_CIPHER_PREFERENCES, "Invalid Cipher Preferences version")
    ERROR_STRING(S2N_ERR_APPLICATION_PROTOCOL_TOO_LONG, "Application protocol name is too long")
    ERROR_STRING(S2N_ERR_NO_APPLICATION_PROTOCOL, "No supported application protocol to negotiate")
    ERROR_STRING(S2N_ERR_DRBG, "Error using Deterministic Random Bit Generator")
    ERROR_STRING(S2N_ERR_DRBG_REQUEST_SIZE, "Request for too much entropy")
    ERROR_STRING(S2N_ERR_ECDHE_GEN_KEY, "Failed to generate an ECDHE key")
    ERROR_STRING(S2N_ERR_ECDHE_SHARED_SECRET, "Error computing ECDHE shared secret")
    ERROR_STRING(S2N_ERR_ECDHE_UNSUPPORTED_CURVE, "Unsupported EC curve was presented during an ECDHE handshake")
    ERROR_STRING(S2N_ERR_ECDHE_SERIALIZING, "Error serializing ECDHE public")
    ERROR_STRING(S2N_ERR_KEM_UNSUPPORTED_PARAMS, "Unsupported KEM params was presented during a handshake that uses a KEM")
    ERROR_STRING(S2N_ERR_SHUTDOWN_PAUSED, "s2n_shutdown() called while paused")
    ERROR_STRING(S2N_ERR_SHUTDOWN_CLOSED, "Peer closed before sending their close_notify")
    ERROR_STRING(S2N_ERR_SHUTDOWN_RECORD_TYPE, "Non alert record received during s2n_shutdown()")
    ERROR_STRING(S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO, "renegotiation_info should be empty")
    ERROR_STRING(S2N_ERR_SEND_SIZE, "Retried s2n_send() size is invalid")
    ERROR_STRING(S2N_ERR_KEY_CHECK, "Invalid key")
    ERROR_STRING(S2N_ERR_CIPHER_TYPE, "Unknown cipher type used")
    ERROR_STRING(S2N_ERR_MAP_DUPLICATE, "Duplicate map key inserted")
    ERROR_STRING(S2N_ERR_MAP_IMMUTABLE, "Attempt to update an immutable map")
    ERROR_STRING(S2N_ERR_MAP_MUTABLE, "Attempt to lookup a mutable map")
    ERROR_STRING(S2N_ERR_INITIAL_HMAC, "error calling EVP_CIPHER_CTX_ctrl for composite cbc cipher")
    ERROR_STRING(S2N_ERR_RECORD_LIMIT, "TLS record limit reached")
    ERROR_STRING(S2N_ERR_CORK_SET_ON_UNMANAGED, "Attempt to set connection cork management on unmanaged IO")
    ERROR_STRING(S2N_ERR_UNRECOGNIZED_EXTENSION, "TLS extension not recognized" )
    ERROR_STRING(S2N_ERR_INVALID_SCT_LIST, "SCT list is invalid" )
    ERROR_STRING(S2N_ERR_INVALID_OCSP_RESPONSE, "OCSP response is invalid" )
    ERROR_STRING(S2N_ERR_UPDATING_EXTENSION, "Updating extension data failed" )
    ERROR_STRING(S2N_ERR_INVALID_NONCE_TYPE, "Invalid AEAD nonce type")
    ERROR_STRING(S2N_ERR_UNIMPLEMENTED, "Unimplemented feature")
    ERROR_STRING(S2N_ERR_READ, "error calling read")
    ERROR_STRING(S2N_ERR_WRITE, "error calling write")
    ERROR_STRING(S2N_ERR_CERT_UNTRUSTED, "Certificate is untrusted")
    ERROR_STRING(S2N_ERR_CERT_TYPE_UNSUPPORTED, "Certificate Type is unsupported")
    ERROR_STRING(S2N_ERR_CANCELLED, "handshake was cancelled")
    ERROR_STRING(S2N_ERR_INVALID_MAX_FRAG_LEN, "invalid Maximum Fragmentation Length encountered")
    ERROR_STRING(S2N_ERR_MAX_FRAG_LEN_MISMATCH, "Negotiated Maximum Fragmentation Length from server does not match the requested length by client")
    ERROR_STRING(S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED, "TLS protocol version is not supported by selected cipher suite")
    ERROR_STRING(S2N_ERR_INVALID_SERIALIZED_SESSION_STATE, "Serialized session state is not in valid format")
    ERROR_STRING(S2N_ERR_SERIALIZED_SESSION_STATE_TOO_LONG, "Serialized session state is too long")
    ERROR_STRING(S2N_ERR_SESSION_ID_TOO_LONG, "Session id is too long")
    ERROR_STRING(S2N_ERR_SESSION_ID_TOO_SHORT, "Session id is too short")
    ERROR_STRING(S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_SESSION_RESUMPTION_MODE, "Client Auth is not supported in session resumption mode")
    ERROR_STRING(S2N_ERR_INVALID_TICKET_KEY_LENGTH, "Session ticket key length cannot be zero")
    ERROR_STRING(S2N_ERR_INVALID_TICKET_KEY_NAME_OR_NAME_LENGTH, "Session ticket key name should be unique and the name length cannot be zero")
    ERROR_STRING(S2N_ERR_TICKET_KEY_NOT_UNIQUE, "Cannot add session ticket key because it was added before")
    ERROR_STRING(S2N_ERR_TICKET_KEY_LIMIT, "Limit reached for unexpired session ticket keys")
    ERROR_STRING(S2N_ERR_NO_TICKET_ENCRYPT_DECRYPT_KEY, "No key in encrypt-decrypt state is available to encrypt session ticket")
    ERROR_STRING(S2N_ERR_ENCRYPT_DECRYPT_KEY_SELECTION_FAILED, "Failed to select a key from keys in encrypt-decrypt state")
    ERROR_STRING(S2N_ERR_KEY_USED_IN_SESSION_TICKET_NOT_FOUND, "Key used in already assigned session ticket not found for decryption")
    ERROR_STRING(S2N_ERR_SENDING_NST, "Error in session ticket status encountered before sending NST")
    ERROR_STRING(S2N_ERR_INVALID_DYNAMIC_THRESHOLD, "invalid dynamic record threshold")
    ERROR_STRING(S2N_ERR_INVALID_ARGUMENT, "invalid argument provided into a function call")
    ERROR_STRING(S2N_ERR_NOT_IN_UNIT_TEST, "Illegal configuration, can only be used during unit tests")
    ERROR_STRING(S2N_ERR_BAD_FD, "Invalid file descriptor")
    ERROR_STRING(S2N_ERR_RDRAND_FAILED, "Error executing rdrand instruction")
    ERROR_STRING(S2N_ERR_UNSUPPORTED_CPU, "Unsupported CPU architecture")
    ERROR_STRING(S2N_ERR_FAILED_CACHE_RETRIEVAL, "Failed cache retrieval")
    ERROR_STRING(S2N_ERR_CONNECTION_CACHING_DISALLOWED, "This connection is not allowed to be cached")
    ERROR_STRING(S2N_ERR_SESSION_TICKET_NOT_SUPPORTED, "Session ticket not supported for this connection")
    ERROR_STRING(S2N_ERR_X509_TRUST_STORE, "Error initializing trust store")
    ERROR_STRING(S2N_ERR_UNKNOWN_PROTOCOL_VERSION, "Error determining client protocol version")
    ERROR_STRING(S2N_ERR_OCSP_NOT_SUPPORTED, "OCSP stapling was requested, but is not supported")
    ERROR_STRING(S2N_ERR_NULL_CN_NAME, "Error parsing CN names")
    ERROR_STRING(S2N_ERR_NULL_SANS, "Error parsing SANS")
    ERROR_STRING(S2N_ERR_CLIENT_HELLO_VERSION, "Could not get client hello version")
    ERROR_STRING(S2N_ERR_CLIENT_PROTOCOL_VERSION, "Could not get client protocol version")
    ERROR_STRING(S2N_ERR_SERVER_PROTOCOL_VERSION, "Could not get server protocol version")
    ERROR_STRING(S2N_ERR_ACTUAL_PROTOCOL_VERSION, "Could not get actual protocol version")
    ERROR_STRING(S2N_ERR_POLLING_FROM_SOCKET, "Error polling from socket")
    ERROR_STRING(S2N_ERR_RECV_STUFFER_FROM_CONN, "Error receiving stuffer from connection")
    ERROR_STRING(S2N_ERR_SEND_STUFFER_TO_CONN, "Error sending stuffer to connection")
};
const int num_of_errors = sizeof(S2N_ERROR_EN) / sizeof(S2N_ERROR_EN[0]);
static struct s2n_map *error_translation_table = NULL;

typedef union {
    uint8_t bytes[sizeof(int)];
    int raw;
} key_type;

typedef union {
    uint8_t bytes[sizeof(uintptr_t)];
    uintptr_t raw;
} value_type;

static struct s2n_error_translation *s2n_lookup_error_translation(int error)
{
    if (error_translation_table == NULL) {
        /* Since error_translation_table should be initialized early
         * in s2n_init(), error_translation_table can be only be NULL if
         * 1. an error is thrown before i.e. s2n_fips_init()
         * 2. s2n_error_table_init() fails when allocating memory
         *
         * In these cases, fall back to O(N) approach of iterating error strings
         */
        for (int i = 0; i < num_of_errors; ++i) {
            if (S2N_ERROR_EN[i].errno_value == error) {
                return &S2N_ERROR_EN[i];
            }
        }
        return NULL;
    }

    struct s2n_blob k, v;
    key_type key = {0};
    key.raw = error;
    k.data = key.bytes;
    k.size = sizeof(key.bytes);
    if (s2n_map_lookup(error_translation_table, &k, &v) != 1) {
        return NULL;
    }

    value_type address = {0};
    memcpy(address.bytes, v.data, v.size);

    return (struct s2n_error_translation*) address.raw;
}

const char *s2n_strerror(int error, const char *lang)
{
    if (lang == NULL) {
        lang = "EN";
    }

    if (strcasecmp(lang, "EN")) {
        return no_such_language;
    }

    struct s2n_error_translation *translation = s2n_lookup_error_translation(error);
    if (NULL == translation) {
        return no_such_error;
    }

    return translation->str;
}

const char *s2n_strerror_name(int error)
{
    struct s2n_error_translation *translation = s2n_lookup_error_translation(error);
    if (NULL == translation) {
        return no_such_error;
    }

    return translation->error_name;
}

const char *s2n_strerror_debug(int error, const char *lang)
{
    if (lang == NULL) {
        lang = "EN";
    }

    if (strcasecmp(lang, "EN")) {
        return no_such_language;
    }

    /* No error, just return the no error string */
    if (error == S2N_ERR_OK) {
        return s2n_strerror(error, lang);
    }

    return s2n_debug_str;
}

int s2n_error_get_type(int error)
{
    return (error >> S2N_ERR_NUM_VALUE_BITS);
}

int s2n_error_table_init()
{
    if (error_translation_table) {
        return 0;
    }

    /* The hash table array uses double size of error array to minimize collisions. */
    int table_size = num_of_errors * 2;
    error_translation_table = s2n_map_new_with_initial_capacity(table_size);
    if (NULL == error_translation_table) {
        S2N_ERROR(S2N_ERR_ALLOC);
    }   

    struct s2n_blob k, v;
    for (int i = 0; i < num_of_errors; ++i) {
        key_type key = {0};
        key.raw = S2N_ERROR_EN[i].errno_value;
        k.data = key.bytes;
        k.size = sizeof(key.bytes);
        value_type address = {0};
        address.raw = (uintptr_t)&S2N_ERROR_EN[i];
        v.data = address.bytes;
        v.size = sizeof(address.bytes);
        if (s2n_map_add(error_translation_table, &k, &v) != 0) {
            S2N_ERROR(S2N_ERR_ALLOC);
        }
    }
    
    GUARD(s2n_map_complete(error_translation_table));

    return 0;
}

void s2n_error_table_cleanup() 
{
    if (NULL == error_translation_table) {
        return;
    }

    s2n_map_free(error_translation_table);
    error_translation_table = NULL;
}
