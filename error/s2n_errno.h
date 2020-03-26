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

/* Order of values in this enum is important. New error values should be placed at the end of their respective category.
 * For example, a new TLS protocol related error belongs in the S2N_ERR_T_PROTO category. It should be placed
 * immediately before S2N_ERR_T_INTERNAL_START(the first value of he next category).
 */
typedef enum {
    /* S2N_ERR_T_OK */
    S2N_ERR_OK = S2N_ERR_T_OK_START,
    S2N_ERR_T_OK_END,

    /* S2N_ERR_T_IO */
    S2N_ERR_IO = S2N_ERR_T_IO_START,
    S2N_ERR_T_IO_END,

    /* S2N_ERR_T_CLOSED */
    S2N_ERR_CLOSED = S2N_ERR_T_CLOSED_START,
    S2N_ERR_T_CLOSED_END,

    /* S2N_ERR_T_BLOCKED */
    S2N_ERR_BLOCKED = S2N_ERR_T_BLOCKED_START,
    S2N_ERR_T_BLOCKED_END,

    /* S2N_ERR_T_ALERT */
    S2N_ERR_ALERT = S2N_ERR_T_ALERT_START,
    S2N_ERR_T_ALERT_END,

    /* S2N_ERR_T_PROTO */
    S2N_ERR_ENCRYPT = S2N_ERR_T_PROTO_START,
    S2N_ERR_DECRYPT,
    S2N_ERR_BAD_MESSAGE,
    S2N_ERR_KEY_INIT,
    S2N_ERR_DH_SERIALIZING,
    S2N_ERR_DH_SHARED_SECRET,
    S2N_ERR_DH_WRITING_PUBLIC_KEY,
    S2N_ERR_DH_FAILED_SIGNING,
    S2N_ERR_DH_COPYING_PARAMETERS,
    S2N_ERR_DH_GENERATING_PARAMETERS,
    S2N_ERR_CIPHER_NOT_SUPPORTED,
    S2N_ERR_NO_APPLICATION_PROTOCOL,
    S2N_ERR_FALLBACK_DETECTED,
    S2N_ERR_HASH_DIGEST_FAILED,
    S2N_ERR_HASH_INIT_FAILED,
    S2N_ERR_HASH_UPDATE_FAILED,
    S2N_ERR_HASH_COPY_FAILED,
    S2N_ERR_HASH_WIPE_FAILED,
    S2N_ERR_HASH_NOT_READY,
    S2N_ERR_ALLOW_MD5_FOR_FIPS_FAILED,
    S2N_ERR_DECODE_CERTIFICATE,
    S2N_ERR_DECODE_PRIVATE_KEY,
    S2N_ERR_INVALID_SIGNATURE_ALGORITHM,
    S2N_ERR_INVALID_SIGNATURE_SCHEME,
    S2N_ERR_EMPTY_SIGNATURE_SCHEME,
    S2N_ERR_CBC_VERIFY,
    S2N_ERR_DH_COPYING_PUBLIC_KEY,
    S2N_ERR_SIGN,
    S2N_ERR_VERIFY_SIGNATURE,
    S2N_ERR_ECDHE_GEN_KEY,
    S2N_ERR_ECDHE_SHARED_SECRET,
    S2N_ERR_ECDHE_UNSUPPORTED_CURVE,
    S2N_ERR_ECDSA_UNSUPPORTED_CURVE,
    S2N_ERR_ECDHE_SERIALIZING,
    S2N_ERR_KEM_UNSUPPORTED_PARAMS,
    S2N_ERR_SHUTDOWN_RECORD_TYPE,
    S2N_ERR_SHUTDOWN_CLOSED,
    S2N_ERR_NON_EMPTY_RENEGOTIATION_INFO,
    S2N_ERR_RECORD_LIMIT,
    S2N_ERR_CERT_UNTRUSTED,
    S2N_ERR_CERT_TYPE_UNSUPPORTED,
    S2N_ERR_INVALID_MAX_FRAG_LEN,
    S2N_ERR_MAX_FRAG_LEN_MISMATCH,
    S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED,
    S2N_ERR_BAD_KEY_SHARE,
    S2N_ERR_CANCELLED,
    S2N_ERR_PROTOCOL_DOWNGRADE_DETECTED,
    S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS,
    S2N_ERR_MAX_INNER_PLAINTEXT_SIZE,
    S2N_ERR_T_PROTO_END,

    /* S2N_ERR_T_INTERNAL */
    S2N_ERR_MADVISE = S2N_ERR_T_INTERNAL_START,
    S2N_ERR_ALLOC,
    S2N_ERR_MLOCK,
    S2N_ERR_MUNLOCK,
    S2N_ERR_FSTAT,
    S2N_ERR_OPEN,
    S2N_ERR_MMAP,
    S2N_ERR_ATEXIT,
    S2N_ERR_NOMEM,
    S2N_ERR_NULL,
    S2N_ERR_SAFETY,
    S2N_ERR_NOT_INITIALIZED,
    S2N_ERR_RANDOM_UNINITIALIZED,
    S2N_ERR_OPEN_RANDOM,
    S2N_ERR_RESIZE_STATIC_STUFFER,
    S2N_ERR_RESIZE_TAINTED_STUFFER,
    S2N_ERR_STUFFER_OUT_OF_DATA,
    S2N_ERR_STUFFER_IS_FULL,
    S2N_ERR_STUFFER_NOT_FOUND,
    S2N_ERR_STUFFER_HAS_UNPROCESSED_DATA,
    S2N_ERR_HASH_INVALID_ALGORITHM,
    S2N_ERR_PRF_INVALID_ALGORITHM,
    S2N_ERR_PRF_INVALID_SEED,
    S2N_ERR_P_HASH_INVALID_ALGORITHM,
    S2N_ERR_P_HASH_INIT_FAILED,
    S2N_ERR_P_HASH_UPDATE_FAILED,
    S2N_ERR_P_HASH_FINAL_FAILED,
    S2N_ERR_P_HASH_WIPE_FAILED,
    S2N_ERR_HMAC_INVALID_ALGORITHM,
    S2N_ERR_HKDF_OUTPUT_SIZE,
    S2N_ERR_ALERT_PRESENT,
    S2N_ERR_HANDSHAKE_STATE,
    S2N_ERR_SHUTDOWN_PAUSED,
    S2N_ERR_SIZE_MISMATCH,
    S2N_ERR_DRBG,
    S2N_ERR_DRBG_REQUEST_SIZE,
    S2N_ERR_KEY_CHECK,
    S2N_ERR_CIPHER_TYPE,
    S2N_ERR_MAP_DUPLICATE,
    S2N_ERR_MAP_IMMUTABLE,
    S2N_ERR_MAP_MUTABLE,
    S2N_ERR_MAP_INVALID_MAP_SIZE,
    S2N_ERR_INITIAL_HMAC,
    S2N_ERR_INVALID_NONCE_TYPE,
    S2N_ERR_UNIMPLEMENTED,
    S2N_ERR_READ,
    S2N_ERR_WRITE,
    S2N_ERR_BAD_FD,
    S2N_ERR_RDRAND_FAILED,
    S2N_ERR_FAILED_CACHE_RETRIEVAL,
    S2N_ERR_X509_TRUST_STORE,
    S2N_ERR_UNKNOWN_PROTOCOL_VERSION,
    S2N_ERR_NULL_CN_NAME,
    S2N_ERR_NULL_SANS,
    S2N_ERR_CLIENT_HELLO_VERSION,
    S2N_ERR_CLIENT_PROTOCOL_VERSION,
    S2N_ERR_SERVER_PROTOCOL_VERSION,
    S2N_ERR_ACTUAL_PROTOCOL_VERSION,
    S2N_ERR_POLLING_FROM_SOCKET,
    S2N_ERR_RECV_STUFFER_FROM_CONN,
    S2N_ERR_SEND_STUFFER_TO_CONN,
    S2N_ERR_PRECONDITION_VIOLATION,
    S2N_ERR_INTEGER_OVERFLOW,
    S2N_ERR_ARRAY_INDEX_OOB,
    S2N_ERR_FREE_STATIC_BLOB,
    S2N_ERR_RESIZE_STATIC_BLOB,
    S2N_ERR_NO_AVAILABLE_BORINGSSL_API,
    S2N_ERR_T_INTERNAL_END,

    /* S2N_ERR_T_USAGE */
    S2N_ERR_NO_ALERT = S2N_ERR_T_USAGE_START,
    S2N_ERR_CLIENT_MODE,
    S2N_ERR_CLIENT_MODE_DISABLED,
    S2N_ERR_TOO_MANY_CERTIFICATES,
    S2N_ERR_TOO_MANY_SIGNATURE_SCHEMES,
    S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_FIPS_MODE,
    S2N_ERR_INVALID_BASE64,
    S2N_ERR_INVALID_HEX,
    S2N_ERR_INVALID_PEM,
    S2N_ERR_DH_PARAMS_CREATE,
    S2N_ERR_DH_TOO_SMALL,
    S2N_ERR_DH_PARAMETER_CHECK,
    S2N_ERR_INVALID_PKCS3,
    S2N_ERR_NO_CERTIFICATE_IN_PEM,
    S2N_ERR_SERVER_NAME_TOO_LONG,
    S2N_ERR_NUM_DEFAULT_CERTIFICATES,
    S2N_ERR_MULTIPLE_DEFAULT_CERTIFICATES_PER_AUTH_TYPE,
    S2N_ERR_INVALID_CIPHER_PREFERENCES,
    S2N_ERR_APPLICATION_PROTOCOL_TOO_LONG,
    S2N_ERR_KEY_MISMATCH,
    S2N_ERR_SEND_SIZE,
    S2N_ERR_CORK_SET_ON_UNMANAGED,
    S2N_ERR_UNRECOGNIZED_EXTENSION,
    S2N_ERR_INVALID_SCT_LIST,
    S2N_ERR_INVALID_OCSP_RESPONSE,
    S2N_ERR_UPDATING_EXTENSION,
    S2N_ERR_INVALID_SERIALIZED_SESSION_STATE,
    S2N_ERR_SERIALIZED_SESSION_STATE_TOO_LONG,
    S2N_ERR_SESSION_ID_TOO_LONG,
    S2N_ERR_CLIENT_AUTH_NOT_SUPPORTED_IN_SESSION_RESUMPTION_MODE,
    S2N_ERR_INVALID_TICKET_KEY_LENGTH,
    S2N_ERR_INVALID_TICKET_KEY_NAME_OR_NAME_LENGTH,
    S2N_ERR_TICKET_KEY_NOT_UNIQUE,
    S2N_ERR_TICKET_KEY_LIMIT,
    S2N_ERR_NO_TICKET_ENCRYPT_DECRYPT_KEY,
    S2N_ERR_ENCRYPT_DECRYPT_KEY_SELECTION_FAILED,
    S2N_ERR_KEY_USED_IN_SESSION_TICKET_NOT_FOUND,
    S2N_ERR_SENDING_NST,
    S2N_ERR_INVALID_DYNAMIC_THRESHOLD,
    S2N_ERR_INVALID_ARGUMENT,
    S2N_ERR_NOT_IN_UNIT_TEST,
    S2N_ERR_UNSUPPORTED_CPU,
    S2N_ERR_SESSION_ID_TOO_SHORT,
    S2N_ERR_CONNECTION_CACHING_DISALLOWED,
    S2N_ERR_SESSION_TICKET_NOT_SUPPORTED,
    S2N_ERR_OCSP_NOT_SUPPORTED,
    S2N_ERR_INVALID_SIGNATURE_ALGORITHMS_PREFERENCES,
    S2N_RSA_PSS_NOT_SUPPORTED,
    S2N_ERR_INVALID_ECC_PREFERENCES,
    S2N_ERR_T_USAGE_END,
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

#ifdef __TIMING_CONTRACTS__
#    define S2N_PRECONDITION( cond ) (void) 0
#    define S2N_PRECONDITION_PTR( cond ) (void) 0
#else
#    define S2N_PRECONDITION( cond ) S2N_ERROR_IF(!(cond), S2N_ERR_PRECONDITION_VIOLATION)
#    define S2N_PRECONDITION_PTR( cond ) S2N_ERROR_IF_PTR(!(cond), S2N_ERR_PRECONDITION_VIOLATION)
#endif /* __TIMING_CONTRACTS__ */

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

#define S2N_IMPLIES(a, b) (!(a) || (b))

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
