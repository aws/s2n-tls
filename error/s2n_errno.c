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
#include <stdlib.h>

#include "error/s2n_errno.h"

#include <s2n.h>

__thread int s2n_errno;
__thread const char *s2n_debug_str;

static const char *no_such_language = "Language is not supported for error translation";
static const char *no_such_error = "Internal s2n error";

struct s2n_error_translation {
    int errno_value;
    const char *str;
};

struct s2n_error_translation S2N_ERROR_EN[] = {
    {S2N_ERR_OK, "no error"},
    {S2N_ERR_IO, "underlying I/O operation failed, check system errno"},
    {S2N_ERR_BLOCKED, "underlying I/O operation would block"},
    {S2N_ERR_KEY_INIT, "error initializing encryption key"},
    {S2N_ERR_ENCRYPT, "error encrypting data"},
    {S2N_ERR_DECRYPT, "error decrypting data"},
    {S2N_ERR_MADVISE, "error calling madvise"},
    {S2N_ERR_ALLOC, "error allocating memory"},
    {S2N_ERR_MLOCK, "error calling mlock (Did you run prlimit?)"},
    {S2N_ERR_MUNLOCK, "error calling munlock"},
    {S2N_ERR_FSTAT, "error calling fstat"},
    {S2N_ERR_OPEN, "error calling open"},
    {S2N_ERR_MMAP, "error calling mmap"},
    {S2N_ERR_ATEXIT, "error calling atexit"},
    {S2N_ERR_NULL, "NULL pointer encountered"},
    {S2N_ERR_CLOSED, "connection is closed"},
    {S2N_ERR_SAFETY, "a safety check failed"},
    {S2N_ERR_NOT_INITIALIZED, "s2n not initialized"},
    {S2N_ERR_RANDOM_UNINITIALIZED, "s2n entropy not initialized"},
    {S2N_ERR_OPEN_RANDOM, "error opening urandom"},
    {S2N_ERR_RESIZE_STATIC_STUFFER, "cannot resize a static stuffer"},
    {S2N_ERR_RESIZE_TAINTED_STUFFER, "cannot resize a tainted stuffer"},
    {S2N_ERR_STUFFER_OUT_OF_DATA, "stuffer is out of data"},
    {S2N_ERR_STUFFER_IS_FULL, "stuffer is full"},
    {S2N_ERR_STUFFER_NOT_FOUND, "stuffer expected bytes were not found"},
    {S2N_ERR_INVALID_BASE64, "invalid base64 encountered"},
    {S2N_ERR_INVALID_PEM, "invalid PEM encountered"},
    {S2N_ERR_DH_COPYING_PARAMETERS, "error copying Diffie-Hellman parameters"},
    {S2N_ERR_DH_COPYING_PUBLIC_KEY, "error copying Diffie-Hellman public key"},
    {S2N_ERR_DH_GENERATING_PARAMETERS, "error generating Diffie-Hellman parameters"},
    {S2N_ERR_DH_PARAMS_CREATE, "error creating Diffie-Hellman parameters"},
    {S2N_ERR_DH_SERIALIZING, "error serializing Diffie-Hellman parameters"},
    {S2N_ERR_DH_SHARED_SECRET, "error computing Diffie-Hellman shared secret"},
    {S2N_ERR_DH_WRITING_PUBLIC_KEY, "error writing Diffie-Hellman public key"},
    {S2N_ERR_DH_FAILED_SIGNING, "error signing Diffie-Hellman values"},
    {S2N_ERR_DH_TOO_SMALL, "Diffie-Hellman parameters are too small"},
    {S2N_ERR_DH_PARAMETER_CHECK, "Diffie-Hellman parameter check failed"},
    {S2N_ERR_INVALID_PKCS3, "invalid PKCS3 encountered"},
    {S2N_ERR_HASH_DIGEST_FAILED, "failed to create hash digest"},
    {S2N_ERR_HASH_INIT_FAILED, "error initializing hash"},
    {S2N_ERR_HASH_INVALID_ALGORITHM, "invalid hash algorithm"},
    {S2N_ERR_HASH_UPDATE_FAILED, "error updating hash"},
    {S2N_ERR_HASH_COPY_FAILED, "error copying hash"},
    {S2N_ERR_HASH_WIPE_FAILED, "error wiping hash"},
    {S2N_ERR_HASH_NOT_READY, "hash not in a valid state for the attempted operation"},
    {S2N_ERR_ALLOW_MD5_FOR_FIPS_FAILED, "error allowing MD5 to be used when in FIPS mode"},
    {S2N_ERR_HMAC_INVALID_ALGORITHM, "invalid HMAC algorithm"},
    {S2N_ERR_HKDF_OUTPUT_SIZE, "invalid HKDF output size"},
    {S2N_ERR_PRF_INVALID_ALGORITHM, "invalid prf hash algorithm"},
    {S2N_ERR_PRF_INVALID_SEED, "invalid prf seeds provided"},
    {S2N_ERR_P_HASH_INVALID_ALGORITHM, "invalid p_hash algorithm"},
    {S2N_ERR_P_HASH_INIT_FAILED, "error initializing p_hash"},
    {S2N_ERR_P_HASH_UPDATE_FAILED, "error updating p_hash"},
    {S2N_ERR_P_HASH_FINAL_FAILED, "error creating p_hash digest"},
    {S2N_ERR_P_HASH_WIPE_FAILED, "error wiping p_hash"},
    {S2N_ERR_SIZE_MISMATCH, "size mismatch"},
    {S2N_ERR_DECODE_CERTIFICATE, "error decoding certificate"},
    {S2N_ERR_DECODE_PRIVATE_KEY, "error decoding private key"},
    {S2N_ERR_KEY_MISMATCH, "public and private key do not match"},
    {S2N_ERR_NOMEM, "no memory"},
    {S2N_ERR_SIGN, "error signing data"},
    {S2N_ERR_VERIFY_SIGNATURE, "error verifying signature"},
    {S2N_ERR_ALERT_PRESENT, "TLS alert is already pending"},
    {S2N_ERR_ALERT, "TLS alert received"},
    {S2N_ERR_CBC_VERIFY, "Failed CBC verification"},
    {S2N_ERR_CIPHER_NOT_SUPPORTED, "Cipher is not supported"},
    {S2N_ERR_BAD_MESSAGE, "Bad message encountered"},
    {S2N_ERR_INVALID_SIGNATURE_ALGORITHM, "Invalid signature algorithm"},
    {S2N_ERR_NO_CERTIFICATE_IN_PEM, "No certificate in PEM"},
    {S2N_ERR_NO_ALERT, "No Alert present"},
    {S2N_ERR_CLIENT_MODE, "operation not allowed in client mode"},
    {S2N_ERR_SERVER_NAME_TOO_LONG, "server name is too long"},
    {S2N_ERR_CLIENT_MODE_DISABLED, "client connections not allowed"},
    {S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_FIPS_MODE, "Client Auth is not supported when in FIPS mode"},
    {S2N_ERR_HANDSHAKE_STATE, "Invalid handshake state encountered"},
    {S2N_ERR_FALLBACK_DETECTED, "TLS fallback detected"},
    {S2N_ERR_INVALID_CIPHER_PREFERENCES, "Invalid Cipher Preferences version"},
    {S2N_ERR_APPLICATION_PROTOCOL_TOO_LONG, "Application protocol name is too long"},
    {S2N_ERR_NO_APPLICATION_PROTOCOL, "No supported application protocol to negotiate"},
    {S2N_ERR_DRBG, "Error using Deterministic Random Bit Generator"},
    {S2N_ERR_DRBG_REQUEST_SIZE, "Request for too much entropy"},
    {S2N_ERR_ECDHE_GEN_KEY, "Failed to generate an ECDHE key"},
    {S2N_ERR_ECDHE_SHARED_SECRET, "Error computing ECDHE shared secret"},
    {S2N_ERR_ECDHE_UNSUPPORTED_CURVE, "Unsupported EC curve was presented during an ECDHE handshake"},
    {S2N_ERR_ECDHE_SERIALIZING, "Error serializing ECDHE public"},
    {S2N_ERR_KEM_UNSUPPORTED_PARAMS, "Unsupported KEM params was presented during a handshake that uses a KEM"},
    {S2N_ERR_SHUTDOWN_PAUSED, "s2n_shutdown() called while paused"},
    {S2N_ERR_SHUTDOWN_CLOSED, "Peer closed before sending their close_notify"},
    {S2N_ERR_SHUTDOWN_RECORD_TYPE, "Non alert record received during s2n_shutdown()"},
    {S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO, "renegotiation_info should be empty"},
    {S2N_ERR_SEND_SIZE, "Retried s2n_send() size is invalid"},
    {S2N_ERR_KEY_CHECK, "Invalid key"},
    {S2N_ERR_CIPHER_TYPE, "Unknown cipher type used"},
    {S2N_ERR_MAP_DUPLICATE, "Duplicate map key inserted"},
    {S2N_ERR_MAP_IMMUTABLE, "Attempt to update an immutable map"},
    {S2N_ERR_MAP_MUTABLE, "Attempt to lookup a mutable map"},
    {S2N_ERR_INITIAL_HMAC, "error calling EVP_CIPHER_CTX_ctrl for composite cbc cipher"},
    {S2N_ERR_RECORD_LIMIT, "TLS record limit reached"},
    {S2N_ERR_CORK_SET_ON_UNMANAGED, "Attempt to set connection cork management on unmanaged IO"},
    {S2N_ERR_UNRECOGNIZED_EXTENSION, "TLS extension not recognized" },
    {S2N_ERR_INVALID_SCT_LIST, "SCT list is invalid" },
    {S2N_ERR_INVALID_OCSP_RESPONSE, "OCSP response is invalid" },
    {S2N_ERR_UPDATING_EXTENSION, "Updating extension data failed" },
    {S2N_ERR_INVALID_NONCE_TYPE, "Invalid AEAD nonce type"},
    {S2N_ERR_UNIMPLEMENTED, "Unimplemented feature"},
    {S2N_ERR_READ, "error calling read"},
    {S2N_ERR_WRITE, "error calling write"},
    {S2N_ERR_CERT_UNTRUSTED, "Certificate is untrusted"},
    {S2N_ERR_CERT_TYPE_UNSUPPORTED, "Certificate Type is unsupported"},
    {S2N_ERR_CANCELLED, "handshake was cancelled"},
    {S2N_ERR_INVALID_MAX_FRAG_LEN, "invalid Maximum Fragmentation Length encountered"},
    {S2N_ERR_MAX_FRAG_LEN_MISMATCH, "Negotiated Maximum Fragmentation Length from server does not match the requested length by client"},
    {S2N_ERR_INVALID_SERIALIZED_SESSION_STATE, "Serialized session state is not in valid format"},
    {S2N_ERR_SERIALIZED_SESSION_STATE_TOO_LONG, "Serialized session state is too long"},
    {S2N_ERR_SESSION_ID_TOO_LONG, "Session id is too long"},
    {S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_SESSION_RESUMPTION_MODE, "Client Auth is not supported in session resumption mode"},
    {S2N_ERR_INVALID_TICKET_KEY_LENGTH, "Session ticket key length cannot be zero"},
    {S2N_ERR_INVALID_TICKET_KEY_NAME_OR_NAME_LENGTH, "Session ticket key name should be unique and the name length cannot be zero"},
    {S2N_ERR_TICKET_KEY_NOT_UNIQUE, "Cannot add session ticket key because it was added before"},
    {S2N_ERR_TICKET_KEY_LIMIT, "Limit reached for unexpired session ticket keys"},
    {S2N_ERR_NO_TICKET_ENCRYPT_DECRYPT_KEY, "No key in encrypt-decrypt state is available to encrypt session ticket"},
    {S2N_ERR_ENCRYPT_DECRYPT_KEY_SELECTION_FAILED, "Failed to select a key from keys in encrypt-decrypt state"},
    {S2N_ERR_KEY_USED_IN_SESSION_TICKET_NOT_FOUND, "Key used in already assigned session ticket not found for decryption"},
    {S2N_ERR_SENDING_NST, "Error in session ticket status encountered before sending NST"},
    {S2N_ERR_INVALID_DYNAMIC_THRESHOLD, "invalid dynamic record threshold"},
    {S2N_ERR_INVALID_ARGUMENT, "invalid argument provided into a function call"},
    {S2N_ERR_NOT_IN_UNIT_TEST, "Illegal configuration, can only be used during unit tests"},
};

const char *s2n_strerror(int error, const char *lang)
{
    if (lang == NULL) {
        lang = "EN";
    }

    if (strcasecmp(lang, "EN")) {
        return no_such_language;
    }

    for (int i = 0; i < (sizeof(S2N_ERROR_EN) / sizeof(struct s2n_error_translation)); i++) {
        if (S2N_ERROR_EN[i].errno_value == error) {
            return S2N_ERROR_EN[i].str;
        }
    }

    return no_such_error;
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
