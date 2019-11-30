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

#pragma once

#include <s2n.h>
#include <stdio.h>
#include <stdbool.h>
/*
 * To easily retrieve error types, we split error values into two parts.
 * The upper 6 bits describe the error type and the lower bits describe the value within the category.
 * [ Error Type Bits(31-26) ][ Value Bits(25-0) ]
 */
#define S2N_ERR_NUM_VALUE_BITS 26

/* Start value for each error type. */
#define S2N_ERR_T_OK_START (S2N_ERR_T_OK << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_IO_START (S2N_ERR_T_IO << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_CLOSED_START (S2N_ERR_T_CLOSED << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_BLOCKED_START (S2N_ERR_T_BLOCKED << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_ALERT_START (S2N_ERR_T_ALERT << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_PROTO_START (S2N_ERR_T_PROTO << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_INTERNAL_START (S2N_ERR_T_INTERNAL << S2N_ERR_NUM_VALUE_BITS)
#define S2N_ERR_T_USAGE_START (S2N_ERR_T_USAGE << S2N_ERR_NUM_VALUE_BITS)

/* Define a macro that would contains entries for errors across all categories
 * This macro takes 3 arguments
 * 1. category macro that generates code around each category
 * 2. entry macro that generates codes for each entry
 * 3. header entry macro that generates each entry with associated category */
#define ALL_ERROR_TYPES(CATEGORY, ENTRY, HEADER_ENTRY) \
    CATEGORY(S2N_ERR_T_OK,       ENTRY, HEADER_ENTRY) \
    CATEGORY(S2N_ERR_T_IO,       ENTRY, HEADER_ENTRY) \
    CATEGORY(S2N_ERR_T_CLOSED,   ENTRY, HEADER_ENTRY) \
    CATEGORY(S2N_ERR_T_BLOCKED,  ENTRY, HEADER_ENTRY) \
    CATEGORY(S2N_ERR_T_ALERT,    ENTRY, HEADER_ENTRY) \
    CATEGORY(S2N_ERR_T_PROTO,    ENTRY, HEADER_ENTRY) \
    CATEGORY(S2N_ERR_T_INTERNAL, ENTRY, HEADER_ENTRY) \
    CATEGORY(S2N_ERR_T_USAGE,    ENTRY, HEADER_ENTRY) \

/* Category enum template. Takes in
 * - category: name of error type
 * - entry: a macro that takes in name and description
 * - header entry: a macro that takes in name, description, category */
#define ERR_ENUM_CATEGORY(category, ENTRY, HEADER_ENTRY) \
    category##_ENTRIES(ENTRY, HEADER_ENTRY, category) \
    category##_END,

#define ERR_ENUM_HEADER_ENTRY(name, description, category) name = category##_START,
#define ERR_ENUM_ENTRY(name, desecription) name,

/*****************************************************************
 * All S2N errors are declared in the follow macros. Each error
 * belongs to an error category type. In each category, the first
 * error uses a macro function "ERR_HEADER_ENTRY" while other use
 * ERR_ENTRY. Each category is also defined as
 * S2N_<ERROR TYPE>_ENTRIES.
 *
 * Placing a new error entry in these macros ease the manual addition
 * of code in s2n_error enum, s2n_strerror, s2n_strerror_name while
 * providing compile time error lookup functions.
 *
 * New error values should be placed at the end of their respective macro category.
 * For example, a new TLS protocol related error belongs in the S2N_ERR_T_PROTO
 * category and should be added to the end of S2N_ERR_T_PROTO_ENTRIES.
 ***********************************************************************/

/**********************************************************
 *            Start error entries macros                  *
 **********************************************************/

/* Special error entry for "No Error" return type */
#define S2N_ERR_T_OK_ENTRIES(ERR_ENTRY, ERR_HEADER_ENTRY, type) \
    ERR_HEADER_ENTRY(S2N_ERR_OK, "no error", type) \

/* Define IO errors */
#define S2N_ERR_T_IO_ENTRIES(ERR_ENTRY, ERR_HEADER_ENTRY, type) \
    ERR_HEADER_ENTRY(S2N_ERR_IO, "underlying I/O operation failed, check system errno", type) \

/* Define closed errors */
#define S2N_ERR_T_CLOSED_ENTRIES(ERR_ENTRY, ERR_HEADER_ENTRY, type) \
    ERR_HEADER_ENTRY(S2N_ERR_CLOSED, "connection is closed", type) \

/* Define blocked errors */
#define S2N_ERR_T_BLOCKED_ENTRIES(ERR_ENTRY, ERR_HEADER_ENTRY, type) \
    ERR_HEADER_ENTRY(S2N_ERR_BLOCKED, "underlying I/O operation would block", type) \

/* Define alert errors */
#define S2N_ERR_T_ALERT_ENTRIES(ERR_ENTRY, ERR_HEADER_ENTRY, type) \
    ERR_HEADER_ENTRY(S2N_ERR_ALERT, "TLS alert received", type) \

/* Define TLS protocol related errors */
#define S2N_ERR_T_PROTO_ENTRIES(ERR_ENTRY, ERR_HEADER_ENTRY, type) \
    ERR_HEADER_ENTRY(S2N_ERR_ENCRYPT, "error encrypting data", type) \
    ERR_ENTRY(S2N_ERR_DECRYPT, "error decrypting data") \
    ERR_ENTRY(S2N_ERR_BAD_MESSAGE, "Bad message encountered") \
    ERR_ENTRY(S2N_ERR_KEY_INIT, "error initializing encryption key") \
    ERR_ENTRY(S2N_ERR_DH_SERIALIZING, "error serializing Diffie-Hellman parameters") \
    ERR_ENTRY(S2N_ERR_DH_SHARED_SECRET, "error computing Diffie-Hellman shared secret") \
    ERR_ENTRY(S2N_ERR_DH_WRITING_PUBLIC_KEY, "error writing Diffie-Hellman public key") \
    ERR_ENTRY(S2N_ERR_DH_FAILED_SIGNING, "error signing Diffie-Hellman values") \
    ERR_ENTRY(S2N_ERR_DH_COPYING_PARAMETERS, "error copying Diffie-Hellman parameters") \
    ERR_ENTRY(S2N_ERR_DH_GENERATING_PARAMETERS, "error generating Diffie-Hellman parameters") \
    ERR_ENTRY(S2N_ERR_CIPHER_NOT_SUPPORTED, "Cipher is not supported") \
    ERR_ENTRY(S2N_ERR_NO_APPLICATION_PROTOCOL, "No supported application protocol to negotiate") \
    ERR_ENTRY(S2N_ERR_FALLBACK_DETECTED, "TLS fallback detected") \
    ERR_ENTRY(S2N_ERR_HASH_DIGEST_FAILED, "failed to create hash digest") \
    ERR_ENTRY(S2N_ERR_HASH_INIT_FAILED, "error initializing hash") \
    ERR_ENTRY(S2N_ERR_HASH_UPDATE_FAILED, "error updating hash") \
    ERR_ENTRY(S2N_ERR_HASH_COPY_FAILED, "error copying hash") \
    ERR_ENTRY(S2N_ERR_HASH_WIPE_FAILED, "error wiping hash") \
    ERR_ENTRY(S2N_ERR_HASH_NOT_READY, "hash not in a valid state for the attempted operation") \
    ERR_ENTRY(S2N_ERR_ALLOW_MD5_FOR_FIPS_FAILED, "error allowing MD5 to be used when in FIPS mode") \
    ERR_ENTRY(S2N_ERR_DECODE_CERTIFICATE, "error decoding certificate") \
    ERR_ENTRY(S2N_ERR_DECODE_PRIVATE_KEY, "error decoding private key") \
    ERR_ENTRY(S2N_ERR_INVALID_SIGNATURE_ALGORITHM, "Invalid signature algorithm") \
    ERR_ENTRY(S2N_ERR_CBC_VERIFY, "Failed CBC verification") \
    ERR_ENTRY(S2N_ERR_DH_COPYING_PUBLIC_KEY, "error copying Diffie-Hellman public key") \
    ERR_ENTRY(S2N_ERR_SIGN, "error signing data") \
    ERR_ENTRY(S2N_ERR_VERIFY_SIGNATURE, "error verifying signature") \
    ERR_ENTRY(S2N_ERR_ECDHE_GEN_KEY, "Failed to generate an ECDHE key") \
    ERR_ENTRY(S2N_ERR_ECDHE_SHARED_SECRET, "Error computing ECDHE shared secret") \
    ERR_ENTRY(S2N_ERR_ECDHE_UNSUPPORTED_CURVE, "Unsupported EC curve was presented during an ECDHE handshake") \
    ERR_ENTRY(S2N_ERR_ECDHE_SERIALIZING, "Error serializing ECDHE public") \
    ERR_ENTRY(S2N_ERR_KEM_UNSUPPORTED_PARAMS, "Unsupported KEM params was presented during a handshake that uses a KEM") \
    ERR_ENTRY(S2N_ERR_SHUTDOWN_RECORD_TYPE, "Non alert record received during s2n_shutdown()") \
    ERR_ENTRY(S2N_ERR_SHUTDOWN_CLOSED, "Peer closed before sending their close_notify") \
    ERR_ENTRY(S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO, "renegotiation_info should be empty") \
    ERR_ENTRY(S2N_ERR_RECORD_LIMIT, "TLS record limit reached") \
    ERR_ENTRY(S2N_ERR_CERT_UNTRUSTED, "Certificate is untrusted") \
    ERR_ENTRY(S2N_ERR_CERT_TYPE_UNSUPPORTED, "Certificate Type is unsupported") \
    ERR_ENTRY(S2N_ERR_INVALID_MAX_FRAG_LEN, "invalid Maximum Fragmentation Length encountered") \
    ERR_ENTRY(S2N_ERR_MAX_FRAG_LEN_MISMATCH, "Negotiated Maximum Fragmentation Length from server does not match the requested length by client") \
    ERR_ENTRY(S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED, "TLS protocol version is not supported by selected cipher suite") \
    ERR_ENTRY(S2N_ERR_BAD_KEY_SHARE, "Bad key share received") \

/* Define s2n internal errors */
#define S2N_ERR_T_INTERNAL_ENTRIES(ERR_ENTRY, ERR_HEADER_ENTRY, type) \
    ERR_HEADER_ENTRY(S2N_ERR_MADVISE, "error calling madvise", type) \
    ERR_ENTRY(S2N_ERR_ALLOC, "error allocating memory") \
    ERR_ENTRY(S2N_ERR_MLOCK, "error calling mlock (Did you run prlimit?)") \
    ERR_ENTRY(S2N_ERR_MUNLOCK, "error calling munlock") \
    ERR_ENTRY(S2N_ERR_FSTAT, "error calling fstat") \
    ERR_ENTRY(S2N_ERR_OPEN, "error calling open") \
    ERR_ENTRY(S2N_ERR_MMAP, "error calling mmap") \
    ERR_ENTRY(S2N_ERR_ATEXIT, "error calling atexit") \
    ERR_ENTRY(S2N_ERR_NOMEM, "no memory") \
    ERR_ENTRY(S2N_ERR_NULL, "NULL pointer encountered") \
    ERR_ENTRY(S2N_ERR_SAFETY, "a safety check failed") \
    ERR_ENTRY(S2N_ERR_NOT_INITIALIZED, "s2n not initialized") \
    ERR_ENTRY(S2N_ERR_RANDOM_UNINITIALIZED, "s2n entropy not initialized") \
    ERR_ENTRY(S2N_ERR_OPEN_RANDOM, "error opening urandom") \
    ERR_ENTRY(S2N_ERR_RESIZE_STATIC_STUFFER, "cannot resize a static stuffer") \
    ERR_ENTRY(S2N_ERR_RESIZE_TAINTED_STUFFER, "cannot resize a tainted stuffer") \
    ERR_ENTRY(S2N_ERR_STUFFER_OUT_OF_DATA, "stuffer is out of data") \
    ERR_ENTRY(S2N_ERR_STUFFER_IS_FULL, "stuffer is full") \
    ERR_ENTRY(S2N_ERR_STUFFER_NOT_FOUND, "stuffer expected bytes were not found") \
    ERR_ENTRY(S2N_ERR_STUFFER_HAS_UNPROCESSED_DATA, "stuffer has unprocessed data") \
    ERR_ENTRY(S2N_ERR_HASH_INVALID_ALGORITHM, "invalid hash algorithm") \
    ERR_ENTRY(S2N_ERR_PRF_INVALID_ALGORITHM, "invalid prf hash algorithm") \
    ERR_ENTRY(S2N_ERR_PRF_INVALID_SEED, "invalid prf seeds provided") \
    ERR_ENTRY(S2N_ERR_P_HASH_INVALID_ALGORITHM, "invalid p_hash algorithm") \
    ERR_ENTRY(S2N_ERR_P_HASH_INIT_FAILED, "error initializing p_hash") \
    ERR_ENTRY(S2N_ERR_P_HASH_UPDATE_FAILED, "error updating p_hash") \
    ERR_ENTRY(S2N_ERR_P_HASH_FINAL_FAILED, "error creating p_hash digest") \
    ERR_ENTRY(S2N_ERR_P_HASH_WIPE_FAILED, "error wiping p_hash") \
    ERR_ENTRY(S2N_ERR_HMAC_INVALID_ALGORITHM, "invalid HMAC algorithm") \
    ERR_ENTRY(S2N_ERR_HKDF_OUTPUT_SIZE, "invalid HKDF output size") \
    ERR_ENTRY(S2N_ERR_ALERT_PRESENT, "TLS alert is already pending") \
    ERR_ENTRY(S2N_ERR_HANDSHAKE_STATE, "Invalid handshake state encountered") \
    ERR_ENTRY(S2N_ERR_SHUTDOWN_PAUSED, "s2n_shutdown() called while paused") \
    ERR_ENTRY(S2N_ERR_SIZE_MISMATCH, "size mismatch") \
    ERR_ENTRY(S2N_ERR_DRBG, "Error using Deterministic Random Bit Generator") \
    ERR_ENTRY(S2N_ERR_DRBG_REQUEST_SIZE, "Request for too much entropy") \
    ERR_ENTRY(S2N_ERR_KEY_CHECK, "Invalid key") \
    ERR_ENTRY(S2N_ERR_CIPHER_TYPE, "Unknown cipher type used") \
    ERR_ENTRY(S2N_ERR_MAP_DUPLICATE, "Duplicate map key inserted") \
    ERR_ENTRY(S2N_ERR_MAP_IMMUTABLE, "Attempt to update an immutable map") \
    ERR_ENTRY(S2N_ERR_MAP_MUTABLE, "Attempt to lookup a mutable map") \
    ERR_ENTRY(S2N_ERR_MAP_INVALID_MAP_SIZE, "Attempt to create a map with 0 capacity") \
    ERR_ENTRY(S2N_ERR_INITIAL_HMAC, "error calling EVP_CIPHER_CTX_ctrl for composite cbc cipher") \
    ERR_ENTRY(S2N_ERR_INVALID_NONCE_TYPE, "Invalid AEAD nonce type") \
    ERR_ENTRY(S2N_ERR_UNIMPLEMENTED, "Unimplemented feature") \
    ERR_ENTRY(S2N_ERR_READ, "error calling read") \
    ERR_ENTRY(S2N_ERR_WRITE, "error calling write") \
    ERR_ENTRY(S2N_ERR_BAD_FD, "Invalid file descriptor") \
    ERR_ENTRY(S2N_ERR_RDRAND_FAILED, "Error executing rdrand instruction") \
    ERR_ENTRY(S2N_ERR_FAILED_CACHE_RETRIEVAL, "Failed cache retrieval") \
    ERR_ENTRY(S2N_ERR_X509_TRUST_STORE, "Error initializing trust store") \
    ERR_ENTRY(S2N_ERR_UNKNOWN_PROTOCOL_VERSION, "Error determining client protocol version") \
    ERR_ENTRY(S2N_ERR_NULL_CN_NAME, "Error parsing CN names") \
    ERR_ENTRY(S2N_ERR_NULL_SANS, "Error parsing SANS") \
    ERR_ENTRY(S2N_ERR_CLIENT_HELLO_VERSION, "Could not get client hello version") \
    ERR_ENTRY(S2N_ERR_CLIENT_PROTOCOL_VERSION, "Could not get client protocol version") \
    ERR_ENTRY(S2N_ERR_SERVER_PROTOCOL_VERSION, "Could not get server protocol version") \
    ERR_ENTRY(S2N_ERR_ACTUAL_PROTOCOL_VERSION, "Could not get actual protocol version") \
    ERR_ENTRY(S2N_ERR_POLLING_FROM_SOCKET, "Error polling from socket") \
    ERR_ENTRY(S2N_ERR_RECV_STUFFER_FROM_CONN, "Error receiving stuffer from connection") \
    ERR_ENTRY(S2N_ERR_SEND_STUFFER_TO_CONN, "Error sending stuffer to connection") \
    ERR_ENTRY(S2N_ERR_PRECONDITION_VIOLATION, "Precondition violation") \

/* Define usage errors */
#define S2N_ERR_T_USAGE_ENTRIES(ERR_ENTRY, ERR_HEADER_ENTRY, type) \
    ERR_HEADER_ENTRY(S2N_ERR_NO_ALERT, "No Alert present", type) \
    ERR_ENTRY(S2N_ERR_CLIENT_MODE, "operation not allowed in client mode") \
    ERR_ENTRY(S2N_ERR_CLIENT_MODE_DISABLED, "client connections not allowed") \
    ERR_ENTRY(S2N_ERR_TOO_MANY_CERTIFICATES, "only 1 certificate is supported in client mode") \
    ERR_ENTRY(S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_FIPS_MODE, "Client Auth is not supported when in FIPS mode") \
    ERR_ENTRY(S2N_ERR_INVALID_BASE64, "invalid base64 encountered") \
    ERR_ENTRY(S2N_ERR_INVALID_HEX, "invalid HEX encountered") \
    ERR_ENTRY(S2N_ERR_INVALID_PEM, "invalid PEM encountered") \
    ERR_ENTRY(S2N_ERR_DH_PARAMS_CREATE, "error creating Diffie-Hellman parameters") \
    ERR_ENTRY(S2N_ERR_DH_TOO_SMALL, "Diffie-Hellman parameters are too small") \
    ERR_ENTRY(S2N_ERR_DH_PARAMETER_CHECK, "Diffie-Hellman parameter check failed") \
    ERR_ENTRY(S2N_ERR_INVALID_PKCS3, "invalid PKCS3 encountered") \
    ERR_ENTRY(S2N_ERR_NO_CERTIFICATE_IN_PEM, "No certificate in PEM") \
    ERR_ENTRY(S2N_ERR_SERVER_NAME_TOO_LONG, "server name is too long") \
    ERR_ENTRY(S2N_ERR_NUM_DEFAULT_CERTIFICATES, "exceeded max default certificates or provided no default") \
    ERR_ENTRY(S2N_ERR_MULTIPLE_DEFAULT_CERTIFICATES_PER_AUTH_TYPE, "setting multiple default certificates per auth type is not allowed") \
    ERR_ENTRY(S2N_ERR_INVALID_CIPHER_PREFERENCES, "Invalid Cipher Preferences version") \
    ERR_ENTRY(S2N_ERR_APPLICATION_PROTOCOL_TOO_LONG, "Application protocol name is too long") \
    ERR_ENTRY(S2N_ERR_KEY_MISMATCH, "public and private key do not match") \
    ERR_ENTRY(S2N_ERR_SEND_SIZE, "Retried s2n_send() size is invalid") \
    ERR_ENTRY(S2N_ERR_CORK_SET_ON_UNMANAGED, "Attempt to set connection cork management on unmanaged IO") \
    ERR_ENTRY(S2N_ERR_UNRECOGNIZED_EXTENSION, "TLS extension not recognized") \
    ERR_ENTRY(S2N_ERR_INVALID_SCT_LIST, "SCT list is invalid") \
    ERR_ENTRY(S2N_ERR_INVALID_OCSP_RESPONSE, "OCSP response is invalid") \
    ERR_ENTRY(S2N_ERR_UPDATING_EXTENSION, "Updating extension data failed") \
    ERR_ENTRY(S2N_ERR_CANCELLED, "handshake was cancelled") \
    ERR_ENTRY(S2N_ERR_INVALID_SERIALIZED_SESSION_STATE, "Serialized session state is not in valid format") \
    ERR_ENTRY(S2N_ERR_SERIALIZED_SESSION_STATE_TOO_LONG, "Serialized session state is too long") \
    ERR_ENTRY(S2N_ERR_SESSION_ID_TOO_LONG, "Session id is too long") \
    ERR_ENTRY(S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_SESSION_RESUMPTION_MODE, "Client Auth is not supported in session resumption mode") \
    ERR_ENTRY(S2N_ERR_INVALID_TICKET_KEY_LENGTH, "Session ticket key length cannot be zero") \
    ERR_ENTRY(S2N_ERR_INVALID_TICKET_KEY_NAME_OR_NAME_LENGTH, "Session ticket key name should be unique and the name length cannot be zero") \
    ERR_ENTRY(S2N_ERR_TICKET_KEY_NOT_UNIQUE, "Cannot add session ticket key because it was added before") \
    ERR_ENTRY(S2N_ERR_TICKET_KEY_LIMIT, "Limit reached for unexpired session ticket keys") \
    ERR_ENTRY(S2N_ERR_NO_TICKET_ENCRYPT_DECRYPT_KEY, "No key in encrypt-decrypt state is available to encrypt session ticket") \
    ERR_ENTRY(S2N_ERR_ENCRYPT_DECRYPT_KEY_SELECTION_FAILED, "Failed to select a key from keys in encrypt-decrypt state") \
    ERR_ENTRY(S2N_ERR_KEY_USED_IN_SESSION_TICKET_NOT_FOUND, "Key used in already assigned session ticket not found for decryption") \
    ERR_ENTRY(S2N_ERR_SENDING_NST, "Error in session ticket status encountered before sending NST") \
    ERR_ENTRY(S2N_ERR_INVALID_DYNAMIC_THRESHOLD, "invalid dynamic record threshold") \
    ERR_ENTRY(S2N_ERR_INVALID_ARGUMENT, "invalid argument provided into a function call") \
    ERR_ENTRY(S2N_ERR_NOT_IN_UNIT_TEST, "Illegal configuration, can only be used during unit tests") \
    ERR_ENTRY(S2N_ERR_UNSUPPORTED_CPU, "Unsupported CPU architecture") \
    ERR_ENTRY(S2N_ERR_SESSION_ID_TOO_SHORT, "Session id is too short") \
    ERR_ENTRY(S2N_ERR_CONNECTION_CACHING_DISALLOWED, "This connection is not allowed to be cached") \
    ERR_ENTRY(S2N_ERR_SESSION_TICKET_NOT_SUPPORTED, "Session ticket not supported for this connection") \
    ERR_ENTRY(S2N_ERR_OCSP_NOT_SUPPORTED, "OCSP stapling was requested, but is not supported") \

/**********************************************************
 *              End error entries macros                  *
 **********************************************************/

typedef enum {
    /* the complete list of enums is generated with ALL_ERROR_TYPES and related macros */
    ALL_ERROR_TYPES(ERR_ENUM_CATEGORY, ERR_ENUM_ENTRY, ERR_ENUM_HEADER_ENTRY)
} s2n_error;

#define S2N_DEBUG_STR_LEN 128
extern __thread const char *s2n_debug_str;

#define TO_STRING(s) #s
#define STRING_(s) TO_STRING(s)
#define STRING__LINE__ STRING_(__LINE__)

#define _S2N_DEBUG_LINE     "Error encountered in " __FILE__ " line " STRING__LINE__
#define _S2N_ERROR( x )     do { s2n_debug_str = _S2N_DEBUG_LINE; s2n_errno = ( x ); s2n_calculate_stacktrace(); } while (0)
#define S2N_ERROR( x )      do { _S2N_ERROR( ( x ) ); return -1; } while (0)
#define S2N_ERROR_PRESERVE_ERRNO() do { return -1; } while (0)
#define S2N_ERROR_PTR( x )  do { _S2N_ERROR( ( x ) ); return NULL; } while (0)
#define S2N_ERROR_IF( cond , x ) do { if ( cond ) { S2N_ERROR( x ); }} while (0)
#define S2N_ERROR_IF_PTR( cond , x ) do { if ( cond ) { S2N_ERROR_PTR( x ); }} while (0)

#define S2N_PRECONDITION( cond ) S2N_ERROR_IF(!(cond), S2N_ERR_PRECONDITION_VIOLATION)
#define S2N_PRECONDITION_PTR( cond ) S2N_ERROR_IF_PTR(!(cond), S2N_ERR_PRECONDITION_VIOLATION)

/**
 * Define function contracts.
 * When the code is being verified using CBMC these contracts are formally verified;
 * When the code is built in debug mode, they are checked as much as possible using assertions
 * When the code is built in production mode, non-fatal contracts are not checked.
 * Violations of the function contracts are undefined behaviour.
 */
#ifdef CBMC
#    define S2N_MEM_IS_READABLE(base, len) __CPROVER_r_ok((base), (len))
#    define S2N_MEM_IS_WRITABLE(base, len) __CPROVER_w_ok((base), (len))
#else
/* the C runtime does not give a way to check these properties,
 * but we can at least check that the pointer is valid */
#    define S2N_MEM_IS_READABLE(base, len) (((len) == 0) || (base))
#    define S2N_MEM_IS_WRITABLE(base, len) (((len) == 0) || (base))
#endif /* CBMC */

#define S2N_OBJECT_PTR_IS_READABLE(ptr) S2N_MEM_IS_READABLE((ptr), sizeof(*(ptr)))
#define S2N_OBJECT_PTR_IS_WRITABLE(ptr) S2N_MEM_IS_WRITABLE((ptr), sizeof(*(ptr)))

/** Calculate and print stacktraces */
struct s2n_stacktrace {
  char **trace;
  int trace_size;
};

extern bool s2n_stack_traces_enabled();
extern int s2n_stack_traces_enabled_set(bool newval);

extern int s2n_calculate_stacktrace(void);
extern int s2n_print_stacktrace(FILE *fptr);
extern int s2n_free_stacktrace(void);
extern int s2n_get_stacktrace(struct s2n_stacktrace *trace);
