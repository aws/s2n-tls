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

const char *s2n_strerror(int error, const char *lang)
{
    if (lang == NULL) {
        lang = "EN";
    }

    if (strcasecmp(lang, "EN")) {
        return no_such_language;
    }

    s2n_error err = error;
    switch (err) {
        case S2N_ERR_OK: return "no error";
        case S2N_ERR_IO: return "underlying I/O operation failed, check system errno";
        case S2N_ERR_CLOSED: return "connection is closed";
        case S2N_ERR_BLOCKED: return "underlying I/O operation would block";
        case S2N_ERR_ALERT: return "TLS alert received";
        case S2N_ERR_ENCRYPT: return "error encrypting data";
        case S2N_ERR_DECRYPT: return "error decrypting data";
        case S2N_ERR_BAD_MESSAGE: return "Bad message encountered";
        case S2N_ERR_KEY_INIT: return "error initializing encryption key";
        case S2N_ERR_DH_SERIALIZING: return "error serializing Diffie-Hellman parameters";
        case S2N_ERR_DH_SHARED_SECRET: return "error computing Diffie-Hellman shared secret";
        case S2N_ERR_DH_WRITING_PUBLIC_KEY: return "error writing Diffie-Hellman public key";
        case S2N_ERR_DH_FAILED_SIGNING: return "error signing Diffie-Hellman values";
        case S2N_ERR_DH_COPYING_PARAMETERS: return "error copying Diffie-Hellman parameters";
        case S2N_ERR_DH_GENERATING_PARAMETERS: return "error generating Diffie-Hellman parameters";
        case S2N_ERR_CIPHER_NOT_SUPPORTED: return "Cipher is not supported";
        case S2N_ERR_NO_APPLICATION_PROTOCOL: return "No supported application protocol to negotiate";
        case S2N_ERR_FALLBACK_DETECTED: return "TLS fallback detected";
        case S2N_ERR_HASH_DIGEST_FAILED: return "failed to create hash digest";
        case S2N_ERR_HASH_INIT_FAILED: return "error initializing hash";
        case S2N_ERR_HASH_UPDATE_FAILED: return "error updating hash";
        case S2N_ERR_HASH_COPY_FAILED: return "error copying hash";
        case S2N_ERR_HASH_WIPE_FAILED: return "error wiping hash";
        case S2N_ERR_HASH_NOT_READY: return "hash not in a valid state for the attempted operation";
        case S2N_ERR_ALLOW_MD5_FOR_FIPS_FAILED: return "error allowing MD5 to be used when in FIPS mode";
        case S2N_ERR_DECODE_CERTIFICATE: return "error decoding certificate";
        case S2N_ERR_DECODE_PRIVATE_KEY: return "error decoding private key";
        case S2N_ERR_INVALID_SIGNATURE_ALGORITHM: return "Invalid signature algorithm";
        case S2N_ERR_CBC_VERIFY: return "Failed CBC verification";
        case S2N_ERR_DH_COPYING_PUBLIC_KEY: return "error copying Diffie-Hellman public key";
        case S2N_ERR_SIGN: return "error signing data";
        case S2N_ERR_VERIFY_SIGNATURE: return "error verifying signature";
        case S2N_ERR_ECDHE_GEN_KEY: return "Failed to generate an ECDHE key";
        case S2N_ERR_ECDHE_SHARED_SECRET: return "Error computing ECDHE shared secret";
        case S2N_ERR_ECDHE_UNSUPPORTED_CURVE: return "Unsupported EC curve was presented during an ECDHE handshake";
        case S2N_ERR_ECDHE_SERIALIZING: return "Error serializing ECDHE public";
        case S2N_ERR_KEM_UNSUPPORTED_PARAMS: return "Unsupported KEM params was presented during a handshake that uses a KEM";
        case S2N_ERR_SHUTDOWN_RECORD_TYPE: return "Non alert record received during s2n_shutdown()";
        case S2N_ERR_SHUTDOWN_CLOSED: return "Peer closed before sending their close_notify";
        case S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO: return "renegotiation_info should be empty";
        case S2N_ERR_RECORD_LIMIT: return "TLS record limit reached";
        case S2N_ERR_CERT_UNTRUSTED: return "Certificate is untrusted";
        case S2N_ERR_CERT_TYPE_UNSUPPORTED: return "Certificate Type is unsupported";
        case S2N_ERR_INVALID_MAX_FRAG_LEN: return "invalid Maximum Fragmentation Length encountered";
        case S2N_ERR_MAX_FRAG_LEN_MISMATCH: return "Negotiated Maximum Fragmentation Length from server does not match the requested length by client";
        case S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED: return "TLS protocol version is not supported by selected cipher suite";
        case S2N_ERR_BAD_KEY_SHARE: return "Bad key share received";
        case S2N_ERR_MADVISE: return "error calling madvise";
        case S2N_ERR_ALLOC: return "error allocating memory";
        case S2N_ERR_MLOCK: return "error calling mlock (Did you run prlimit?)";
        case S2N_ERR_MUNLOCK: return "error calling munlock";
        case S2N_ERR_FSTAT: return "error calling fstat";
        case S2N_ERR_OPEN: return "error calling open";
        case S2N_ERR_MMAP: return "error calling mmap";
        case S2N_ERR_ATEXIT: return "error calling atexit";
        case S2N_ERR_NOMEM: return "no memory";
        case S2N_ERR_NULL: return "NULL pointer encountered";
        case S2N_ERR_SAFETY: return "a safety check failed";
        case S2N_ERR_NOT_INITIALIZED: return "s2n not initialized";
        case S2N_ERR_RANDOM_UNINITIALIZED: return "s2n entropy not initialized";
        case S2N_ERR_OPEN_RANDOM: return "error opening urandom";
        case S2N_ERR_RESIZE_STATIC_STUFFER: return "cannot resize a static stuffer";
        case S2N_ERR_RESIZE_TAINTED_STUFFER: return "cannot resize a tainted stuffer";
        case S2N_ERR_STUFFER_OUT_OF_DATA: return "stuffer is out of data";
        case S2N_ERR_STUFFER_IS_FULL: return "stuffer is full";
        case S2N_ERR_STUFFER_NOT_FOUND: return "stuffer expected bytes were not found";
        case S2N_ERR_STUFFER_HAS_UNPROCESSED_DATA: return "stuffer has unprocessed data";
        case S2N_ERR_HASH_INVALID_ALGORITHM: return "invalid hash algorithm";
        case S2N_ERR_PRF_INVALID_ALGORITHM: return "invalid prf hash algorithm";
        case S2N_ERR_PRF_INVALID_SEED: return "invalid prf seeds provided";
        case S2N_ERR_P_HASH_INVALID_ALGORITHM: return "invalid p_hash algorithm";
        case S2N_ERR_P_HASH_INIT_FAILED: return "error initializing p_hash";
        case S2N_ERR_P_HASH_UPDATE_FAILED: return "error updating p_hash";
        case S2N_ERR_P_HASH_FINAL_FAILED: return "error creating p_hash digest";
        case S2N_ERR_P_HASH_WIPE_FAILED: return "error wiping p_hash";
        case S2N_ERR_HMAC_INVALID_ALGORITHM: return "invalid HMAC algorithm";
        case S2N_ERR_HKDF_OUTPUT_SIZE: return "invalid HKDF output size";
        case S2N_ERR_ALERT_PRESENT: return "TLS alert is already pending";
        case S2N_ERR_HANDSHAKE_STATE: return "Invalid handshake state encountered";
        case S2N_ERR_SHUTDOWN_PAUSED: return "s2n_shutdown() called while paused";
        case S2N_ERR_SIZE_MISMATCH: return "size mismatch";
        case S2N_ERR_DRBG: return "Error using Deterministic Random Bit Generator";
        case S2N_ERR_DRBG_REQUEST_SIZE: return "Request for too much entropy";
        case S2N_ERR_KEY_CHECK: return "Invalid key";
        case S2N_ERR_CIPHER_TYPE: return "Unknown cipher type used";
        case S2N_ERR_MAP_DUPLICATE: return "Duplicate map key inserted";
        case S2N_ERR_MAP_IMMUTABLE: return "Attempt to update an immutable map";
        case S2N_ERR_MAP_MUTABLE: return "Attempt to lookup a mutable map";
        case S2N_ERR_MAP_INVALID_MAP_SIZE: return "Attempt to create a map with 0 capacity";
        case S2N_ERR_INITIAL_HMAC: return "error calling EVP_CIPHER_CTX_ctrl for composite cbc cipher";
        case S2N_ERR_INVALID_NONCE_TYPE: return "Invalid AEAD nonce type";
        case S2N_ERR_UNIMPLEMENTED: return "Unimplemented feature";
        case S2N_ERR_READ: return "error calling read";
        case S2N_ERR_WRITE: return "error calling write";
        case S2N_ERR_BAD_FD: return "Invalid file descriptor";
        case S2N_ERR_RDRAND_FAILED: return "Error executing rdrand instruction";
        case S2N_ERR_FAILED_CACHE_RETRIEVAL: return "Failed cache retrieval";
        case S2N_ERR_X509_TRUST_STORE: return "Error initializing trust store";
        case S2N_ERR_UNKNOWN_PROTOCOL_VERSION: return "Error determining client protocol version";
        case S2N_ERR_NULL_CN_NAME: return "Error parsing CN names";
        case S2N_ERR_NULL_SANS: return "Error parsing SANS";
        case S2N_ERR_CLIENT_HELLO_VERSION: return "Could not get client hello version";
        case S2N_ERR_CLIENT_PROTOCOL_VERSION: return "Could not get client protocol version";
        case S2N_ERR_SERVER_PROTOCOL_VERSION: return "Could not get server protocol version";
        case S2N_ERR_ACTUAL_PROTOCOL_VERSION: return "Could not get actual protocol version";
        case S2N_ERR_POLLING_FROM_SOCKET: return "Error polling from socket";
        case S2N_ERR_RECV_STUFFER_FROM_CONN: return "Error receiving stuffer from connection";
        case S2N_ERR_SEND_STUFFER_TO_CONN: return "Error sending stuffer to connection";
        case S2N_ERR_PRECONDITION_VIOLATION: return "Precondition violation";
        case S2N_ERR_NO_ALERT: return "No Alert present";
        case S2N_ERR_CLIENT_MODE: return "operation not allowed in client mode";
        case S2N_ERR_CLIENT_MODE_DISABLED: return "client connections not allowed";
        case S2N_ERR_TOO_MANY_CERTIFICATES: return "only 1 certificate is supported in client mode";
        case S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_FIPS_MODE: return "Client Auth is not supported when in FIPS mode";
        case S2N_ERR_INVALID_BASE64: return "invalid base64 encountered";
        case S2N_ERR_INVALID_HEX: return "invalid HEX encountered";
        case S2N_ERR_INVALID_PEM: return "invalid PEM encountered";
        case S2N_ERR_DH_PARAMS_CREATE: return "error creating Diffie-Hellman parameters";
        case S2N_ERR_DH_TOO_SMALL: return "Diffie-Hellman parameters are too small";
        case S2N_ERR_DH_PARAMETER_CHECK: return "Diffie-Hellman parameter check failed";
        case S2N_ERR_INVALID_PKCS3: return "invalid PKCS3 encountered";
        case S2N_ERR_NO_CERTIFICATE_IN_PEM: return "No certificate in PEM";
        case S2N_ERR_SERVER_NAME_TOO_LONG: return "server name is too long";
        case S2N_ERR_NUM_DEFAULT_CERTIFICATES: return "exceeded max default certificates or provided no default";
        case S2N_ERR_MULTIPLE_DEFAULT_CERTIFICATES_PER_AUTH_TYPE: return "setting multiple default certificates per auth type is not allowed";
        case S2N_ERR_INVALID_CIPHER_PREFERENCES: return "Invalid Cipher Preferences version";
        case S2N_ERR_APPLICATION_PROTOCOL_TOO_LONG: return "Application protocol name is too long";
        case S2N_ERR_KEY_MISMATCH: return "public and private key do not match";
        case S2N_ERR_SEND_SIZE: return "Retried s2n_send() size is invalid";
        case S2N_ERR_CORK_SET_ON_UNMANAGED: return "Attempt to set connection cork management on unmanaged IO";
        case S2N_ERR_UNRECOGNIZED_EXTENSION: return "TLS extension not recognized";
        case S2N_ERR_INVALID_SCT_LIST: return "SCT list is invalid";
        case S2N_ERR_INVALID_OCSP_RESPONSE: return "OCSP response is invalid";
        case S2N_ERR_UPDATING_EXTENSION: return "Updating extension data failed";
        case S2N_ERR_CANCELLED: return "handshake was cancelled";
        case S2N_ERR_INVALID_SERIALIZED_SESSION_STATE: return "Serialized session state is not in valid format";
        case S2N_ERR_SERIALIZED_SESSION_STATE_TOO_LONG: return "Serialized session state is too long";
        case S2N_ERR_SESSION_ID_TOO_LONG: return "Session id is too long";
        case S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_SESSION_RESUMPTION_MODE: return "Client Auth is not supported in session resumption mode";
        case S2N_ERR_INVALID_TICKET_KEY_LENGTH: return "Session ticket key length cannot be zero";
        case S2N_ERR_INVALID_TICKET_KEY_NAME_OR_NAME_LENGTH: return "Session ticket key name should be unique and the name length cannot be zero";
        case S2N_ERR_TICKET_KEY_NOT_UNIQUE: return "Cannot add session ticket key because it was added before";
        case S2N_ERR_TICKET_KEY_LIMIT: return "Limit reached for unexpired session ticket keys";
        case S2N_ERR_NO_TICKET_ENCRYPT_DECRYPT_KEY: return "No key in encrypt-decrypt state is available to encrypt session ticket";
        case S2N_ERR_ENCRYPT_DECRYPT_KEY_SELECTION_FAILED: return "Failed to select a key from keys in encrypt-decrypt state";
        case S2N_ERR_KEY_USED_IN_SESSION_TICKET_NOT_FOUND: return "Key used in already assigned session ticket not found for decryption";
        case S2N_ERR_SENDING_NST: return "Error in session ticket status encountered before sending NST";
        case S2N_ERR_INVALID_DYNAMIC_THRESHOLD: return "invalid dynamic record threshold";
        case S2N_ERR_INVALID_ARGUMENT: return "invalid argument provided into a function call";
        case S2N_ERR_NOT_IN_UNIT_TEST: return "Illegal configuration, can only be used during unit tests";
        case S2N_ERR_UNSUPPORTED_CPU: return "Unsupported CPU architecture";
        case S2N_ERR_SESSION_ID_TOO_SHORT: return "Session id is too short";
        case S2N_ERR_CONNECTION_CACHING_DISALLOWED: return "This connection is not allowed to be cached";
        case S2N_ERR_SESSION_TICKET_NOT_SUPPORTED: return "Session ticket not supported for this connection";
        case S2N_ERR_OCSP_NOT_SUPPORTED: return "OCSP stapling was requested, but is not supported";

        /* Skip block ends */
        case S2N_ERR_T_OK_END:
        case S2N_ERR_T_IO_END:
        case S2N_ERR_T_CLOSED_END:
        case S2N_ERR_T_BLOCKED_END:
        case S2N_ERR_T_ALERT_END:
        case S2N_ERR_T_PROTO_END:
        case S2N_ERR_T_INTERNAL_END:
        case S2N_ERR_T_USAGE_END:
            break;

        /* No default to make compiler fail on missing values */
    }

    return no_such_error;
}

#define CASE_ERROR_NAME(err) case err: return #err
const char *s2n_strerror_name(int error)
{
    s2n_error err = error;
    switch (err) {
        CASE_ERROR_NAME(S2N_ERR_OK);
        CASE_ERROR_NAME(S2N_ERR_IO);
        CASE_ERROR_NAME(S2N_ERR_CLOSED);
        CASE_ERROR_NAME(S2N_ERR_BLOCKED);
        CASE_ERROR_NAME(S2N_ERR_ALERT);
        CASE_ERROR_NAME(S2N_ERR_ENCRYPT);
        CASE_ERROR_NAME(S2N_ERR_DECRYPT);
        CASE_ERROR_NAME(S2N_ERR_BAD_MESSAGE);
        CASE_ERROR_NAME(S2N_ERR_KEY_INIT);
        CASE_ERROR_NAME(S2N_ERR_DH_SERIALIZING);
        CASE_ERROR_NAME(S2N_ERR_DH_SHARED_SECRET);
        CASE_ERROR_NAME(S2N_ERR_DH_WRITING_PUBLIC_KEY);
        CASE_ERROR_NAME(S2N_ERR_DH_FAILED_SIGNING);
        CASE_ERROR_NAME(S2N_ERR_DH_COPYING_PARAMETERS);
        CASE_ERROR_NAME(S2N_ERR_DH_GENERATING_PARAMETERS);
        CASE_ERROR_NAME(S2N_ERR_CIPHER_NOT_SUPPORTED);
        CASE_ERROR_NAME(S2N_ERR_NO_APPLICATION_PROTOCOL);
        CASE_ERROR_NAME(S2N_ERR_FALLBACK_DETECTED);
        CASE_ERROR_NAME(S2N_ERR_HASH_DIGEST_FAILED);
        CASE_ERROR_NAME(S2N_ERR_HASH_INIT_FAILED);
        CASE_ERROR_NAME(S2N_ERR_HASH_UPDATE_FAILED);
        CASE_ERROR_NAME(S2N_ERR_HASH_COPY_FAILED);
        CASE_ERROR_NAME(S2N_ERR_HASH_WIPE_FAILED);
        CASE_ERROR_NAME(S2N_ERR_HASH_NOT_READY);
        CASE_ERROR_NAME(S2N_ERR_ALLOW_MD5_FOR_FIPS_FAILED);
        CASE_ERROR_NAME(S2N_ERR_DECODE_CERTIFICATE);
        CASE_ERROR_NAME(S2N_ERR_DECODE_PRIVATE_KEY);
        CASE_ERROR_NAME(S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
        CASE_ERROR_NAME(S2N_ERR_CBC_VERIFY);
        CASE_ERROR_NAME(S2N_ERR_DH_COPYING_PUBLIC_KEY);
        CASE_ERROR_NAME(S2N_ERR_SIGN);
        CASE_ERROR_NAME(S2N_ERR_VERIFY_SIGNATURE);
        CASE_ERROR_NAME(S2N_ERR_ECDHE_GEN_KEY);
        CASE_ERROR_NAME(S2N_ERR_ECDHE_SHARED_SECRET);
        CASE_ERROR_NAME(S2N_ERR_ECDHE_UNSUPPORTED_CURVE);
        CASE_ERROR_NAME(S2N_ERR_ECDHE_SERIALIZING);
        CASE_ERROR_NAME(S2N_ERR_KEM_UNSUPPORTED_PARAMS);
        CASE_ERROR_NAME(S2N_ERR_SHUTDOWN_RECORD_TYPE);
        CASE_ERROR_NAME(S2N_ERR_SHUTDOWN_CLOSED);
        CASE_ERROR_NAME(S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO);
        CASE_ERROR_NAME(S2N_ERR_RECORD_LIMIT);
        CASE_ERROR_NAME(S2N_ERR_CERT_UNTRUSTED);
        CASE_ERROR_NAME(S2N_ERR_CERT_TYPE_UNSUPPORTED);
        CASE_ERROR_NAME(S2N_ERR_INVALID_MAX_FRAG_LEN);
        CASE_ERROR_NAME(S2N_ERR_MAX_FRAG_LEN_MISMATCH);
        CASE_ERROR_NAME(S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
        CASE_ERROR_NAME(S2N_ERR_BAD_KEY_SHARE);
        CASE_ERROR_NAME(S2N_ERR_MADVISE);
        CASE_ERROR_NAME(S2N_ERR_ALLOC);
        CASE_ERROR_NAME(S2N_ERR_MLOCK);
        CASE_ERROR_NAME(S2N_ERR_MUNLOCK);
        CASE_ERROR_NAME(S2N_ERR_FSTAT);
        CASE_ERROR_NAME(S2N_ERR_OPEN);
        CASE_ERROR_NAME(S2N_ERR_MMAP);
        CASE_ERROR_NAME(S2N_ERR_ATEXIT);
        CASE_ERROR_NAME(S2N_ERR_NOMEM);
        CASE_ERROR_NAME(S2N_ERR_NULL);
        CASE_ERROR_NAME(S2N_ERR_SAFETY);
        CASE_ERROR_NAME(S2N_ERR_NOT_INITIALIZED);
        CASE_ERROR_NAME(S2N_ERR_RANDOM_UNINITIALIZED);
        CASE_ERROR_NAME(S2N_ERR_OPEN_RANDOM);
        CASE_ERROR_NAME(S2N_ERR_RESIZE_STATIC_STUFFER);
        CASE_ERROR_NAME(S2N_ERR_RESIZE_TAINTED_STUFFER);
        CASE_ERROR_NAME(S2N_ERR_STUFFER_OUT_OF_DATA);
        CASE_ERROR_NAME(S2N_ERR_STUFFER_IS_FULL);
        CASE_ERROR_NAME(S2N_ERR_STUFFER_NOT_FOUND);
        CASE_ERROR_NAME(S2N_ERR_STUFFER_HAS_UNPROCESSED_DATA);
        CASE_ERROR_NAME(S2N_ERR_HASH_INVALID_ALGORITHM);
        CASE_ERROR_NAME(S2N_ERR_PRF_INVALID_ALGORITHM);
        CASE_ERROR_NAME(S2N_ERR_PRF_INVALID_SEED);
        CASE_ERROR_NAME(S2N_ERR_P_HASH_INVALID_ALGORITHM);
        CASE_ERROR_NAME(S2N_ERR_P_HASH_INIT_FAILED);
        CASE_ERROR_NAME(S2N_ERR_P_HASH_UPDATE_FAILED);
        CASE_ERROR_NAME(S2N_ERR_P_HASH_FINAL_FAILED);
        CASE_ERROR_NAME(S2N_ERR_P_HASH_WIPE_FAILED);
        CASE_ERROR_NAME(S2N_ERR_HMAC_INVALID_ALGORITHM);
        CASE_ERROR_NAME(S2N_ERR_HKDF_OUTPUT_SIZE);
        CASE_ERROR_NAME(S2N_ERR_ALERT_PRESENT);
        CASE_ERROR_NAME(S2N_ERR_HANDSHAKE_STATE);
        CASE_ERROR_NAME(S2N_ERR_SHUTDOWN_PAUSED);
        CASE_ERROR_NAME(S2N_ERR_SIZE_MISMATCH);
        CASE_ERROR_NAME(S2N_ERR_DRBG);
        CASE_ERROR_NAME(S2N_ERR_DRBG_REQUEST_SIZE);
        CASE_ERROR_NAME(S2N_ERR_KEY_CHECK);
        CASE_ERROR_NAME(S2N_ERR_CIPHER_TYPE);
        CASE_ERROR_NAME(S2N_ERR_MAP_DUPLICATE);
        CASE_ERROR_NAME(S2N_ERR_MAP_IMMUTABLE);
        CASE_ERROR_NAME(S2N_ERR_MAP_MUTABLE);
        CASE_ERROR_NAME(S2N_ERR_MAP_INVALID_MAP_SIZE);
        CASE_ERROR_NAME(S2N_ERR_INITIAL_HMAC);
        CASE_ERROR_NAME(S2N_ERR_INVALID_NONCE_TYPE);
        CASE_ERROR_NAME(S2N_ERR_UNIMPLEMENTED);
        CASE_ERROR_NAME(S2N_ERR_READ);
        CASE_ERROR_NAME(S2N_ERR_WRITE);
        CASE_ERROR_NAME(S2N_ERR_BAD_FD);
        CASE_ERROR_NAME(S2N_ERR_RDRAND_FAILED);
        CASE_ERROR_NAME(S2N_ERR_FAILED_CACHE_RETRIEVAL);
        CASE_ERROR_NAME(S2N_ERR_X509_TRUST_STORE);
        CASE_ERROR_NAME(S2N_ERR_UNKNOWN_PROTOCOL_VERSION);
        CASE_ERROR_NAME(S2N_ERR_NULL_CN_NAME);
        CASE_ERROR_NAME(S2N_ERR_NULL_SANS);
        CASE_ERROR_NAME(S2N_ERR_CLIENT_HELLO_VERSION);
        CASE_ERROR_NAME(S2N_ERR_CLIENT_PROTOCOL_VERSION);
        CASE_ERROR_NAME(S2N_ERR_SERVER_PROTOCOL_VERSION);
        CASE_ERROR_NAME(S2N_ERR_ACTUAL_PROTOCOL_VERSION);
        CASE_ERROR_NAME(S2N_ERR_POLLING_FROM_SOCKET);
        CASE_ERROR_NAME(S2N_ERR_RECV_STUFFER_FROM_CONN);
        CASE_ERROR_NAME(S2N_ERR_SEND_STUFFER_TO_CONN);
	CASE_ERROR_NAME(S2N_ERR_PRECONDITION_VIOLATION);
        CASE_ERROR_NAME(S2N_ERR_NO_ALERT);
        CASE_ERROR_NAME(S2N_ERR_CLIENT_MODE);
        CASE_ERROR_NAME(S2N_ERR_CLIENT_MODE_DISABLED);
        CASE_ERROR_NAME(S2N_ERR_TOO_MANY_CERTIFICATES);
        CASE_ERROR_NAME(S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_FIPS_MODE);
        CASE_ERROR_NAME(S2N_ERR_INVALID_BASE64);
        CASE_ERROR_NAME(S2N_ERR_INVALID_HEX);
        CASE_ERROR_NAME(S2N_ERR_INVALID_PEM);
        CASE_ERROR_NAME(S2N_ERR_DH_PARAMS_CREATE);
        CASE_ERROR_NAME(S2N_ERR_DH_TOO_SMALL);
        CASE_ERROR_NAME(S2N_ERR_DH_PARAMETER_CHECK);
        CASE_ERROR_NAME(S2N_ERR_INVALID_PKCS3);
        CASE_ERROR_NAME(S2N_ERR_NO_CERTIFICATE_IN_PEM);
        CASE_ERROR_NAME(S2N_ERR_SERVER_NAME_TOO_LONG);
        CASE_ERROR_NAME(S2N_ERR_NUM_DEFAULT_CERTIFICATES);
        CASE_ERROR_NAME(S2N_ERR_MULTIPLE_DEFAULT_CERTIFICATES_PER_AUTH_TYPE);
        CASE_ERROR_NAME(S2N_ERR_INVALID_CIPHER_PREFERENCES);
        CASE_ERROR_NAME(S2N_ERR_APPLICATION_PROTOCOL_TOO_LONG);
        CASE_ERROR_NAME(S2N_ERR_KEY_MISMATCH);
        CASE_ERROR_NAME(S2N_ERR_SEND_SIZE);
        CASE_ERROR_NAME(S2N_ERR_CORK_SET_ON_UNMANAGED);
        CASE_ERROR_NAME(S2N_ERR_UNRECOGNIZED_EXTENSION);
        CASE_ERROR_NAME(S2N_ERR_INVALID_SCT_LIST);
        CASE_ERROR_NAME(S2N_ERR_INVALID_OCSP_RESPONSE);
        CASE_ERROR_NAME(S2N_ERR_UPDATING_EXTENSION);
        CASE_ERROR_NAME(S2N_ERR_CANCELLED);
        CASE_ERROR_NAME(S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);
        CASE_ERROR_NAME(S2N_ERR_SERIALIZED_SESSION_STATE_TOO_LONG);
        CASE_ERROR_NAME(S2N_ERR_SESSION_ID_TOO_LONG);
        CASE_ERROR_NAME(S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_SESSION_RESUMPTION_MODE);
        CASE_ERROR_NAME(S2N_ERR_INVALID_TICKET_KEY_LENGTH);
        CASE_ERROR_NAME(S2N_ERR_INVALID_TICKET_KEY_NAME_OR_NAME_LENGTH);
        CASE_ERROR_NAME(S2N_ERR_TICKET_KEY_NOT_UNIQUE);
        CASE_ERROR_NAME(S2N_ERR_TICKET_KEY_LIMIT);
        CASE_ERROR_NAME(S2N_ERR_NO_TICKET_ENCRYPT_DECRYPT_KEY);
        CASE_ERROR_NAME(S2N_ERR_ENCRYPT_DECRYPT_KEY_SELECTION_FAILED);
        CASE_ERROR_NAME(S2N_ERR_KEY_USED_IN_SESSION_TICKET_NOT_FOUND);
        CASE_ERROR_NAME(S2N_ERR_SENDING_NST);
        CASE_ERROR_NAME(S2N_ERR_INVALID_DYNAMIC_THRESHOLD);
        CASE_ERROR_NAME(S2N_ERR_INVALID_ARGUMENT);
        CASE_ERROR_NAME(S2N_ERR_NOT_IN_UNIT_TEST);
        CASE_ERROR_NAME(S2N_ERR_UNSUPPORTED_CPU);
        CASE_ERROR_NAME(S2N_ERR_SESSION_ID_TOO_SHORT);
        CASE_ERROR_NAME(S2N_ERR_CONNECTION_CACHING_DISALLOWED);
        CASE_ERROR_NAME(S2N_ERR_SESSION_TICKET_NOT_SUPPORTED);
        CASE_ERROR_NAME(S2N_ERR_OCSP_NOT_SUPPORTED);

        /* Skip block ends */
        case S2N_ERR_T_OK_END:
        case S2N_ERR_T_IO_END:
        case S2N_ERR_T_CLOSED_END:
        case S2N_ERR_T_BLOCKED_END:
        case S2N_ERR_T_ALERT_END:
        case S2N_ERR_T_PROTO_END:
        case S2N_ERR_T_INTERNAL_END:
        case S2N_ERR_T_USAGE_END:
            break;

        /* No default to make compiler fail on missing values */
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
