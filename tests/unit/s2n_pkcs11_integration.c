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

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <s2n.h>

#include "error/s2n_errno.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_cipher_suites.h"
#include "crypto/s2n_certificate.h"
#include "utils/s2n_safety.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>

#include <pthread.h>

#define CK_PTR    *
#define NULL_PTR    0
#define CK_DEFINE_FUNCTION( returnType, name )             returnType name
#define CK_DECLARE_FUNCTION( returnType, name )            returnType name
#define CK_DECLARE_FUNCTION_POINTER( returnType, name )    returnType( CK_PTR name )
#define CK_CALLBACK_FUNCTION( returnType, name )           returnType( CK_PTR name )
#include "pkcs11.h"

/*
 * DER encoded DigestInfo value for SHA256 to be prefixed to the hash.
 * See https://tools.ietf.org/html/rfc3447#page-43
 */
#define pkcs11SHA256_INFO_PREPEND_TO_RSA_SIG { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 }
#define pkcs11SHA384_INFO_PREPEND_TO_RSA_SIG { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 }
#define pkcs11SHA512_INFO_PREPEND_TO_RSA_SIG { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 }

/* Test config. These parameters are configured to work with the S2N CI, either mimic the CI PKCS #11 setup or modify these to values that work in your setup. */
#define pkcs11_test_slot 0
#define pkcs11_pin "0000"
#define pkcs11_rsa_key_label "rsa-privkey"
#define pkcs11_ecdsa_key_label "ecdsa-privkey"

#define PKCS11_GUARD(method_name, args...) \
    do { \
        CK_FUNCTION_LIST_PTR function_list = NULL; \
        if (C_GetFunctionList(&function_list) != CKR_OK || function_list  == NULL) { \
          return S2N_RESULT_OK; \
        } \
        if (function_list->method_name(args) != CKR_OK) { \
          return S2N_RESULT_OK; \
        } \
    } while(0)

static CK_SESSION_HANDLE session;
static struct s2n_async_pkey_op *pkey_op = NULL;
static struct s2n_connection *pkey_conn = NULL;

static S2N_RESULT prepend_id(s2n_tls_hash_algorithm alg, 
                            struct s2n_blob *hash,
                            struct s2n_blob *hash_oid_buf)
{
    RESULT_GUARD_PTR(hash);
    RESULT_GUARD_PTR(hash_oid_buf);

    const uint8_t sha256_oid_sequence[] = pkcs11SHA256_INFO_PREPEND_TO_RSA_SIG;
    const uint8_t sha384_oid_sequence[] = pkcs11SHA384_INFO_PREPEND_TO_RSA_SIG;
    const uint8_t sha512_oid_sequence[] = pkcs11SHA512_INFO_PREPEND_TO_RSA_SIG;

    const uint8_t * oid_sequence = NULL;
    size_t oid_sequence_size = 0;

    switch (alg) {
        case S2N_TLS_HASH_SHA256:
            oid_sequence = &sha256_oid_sequence[0];
            oid_sequence_size = sizeof(sha256_oid_sequence);
            break;
        case S2N_TLS_HASH_SHA384:
            oid_sequence = &sha384_oid_sequence[0];
            oid_sequence_size = sizeof(sha384_oid_sequence);
            break;
        case S2N_TLS_HASH_SHA512:
            oid_sequence = &sha512_oid_sequence[0];
            oid_sequence_size = sizeof(sha512_oid_sequence);
            break;
        default:
            FAIL_MSG("Received an unexpected hash algorithm for the integration test. Consider updating the integration"
                    " for this new type.");
            break;
    }

    EXPECT_SUCCESS(s2n_realloc(hash_oid_buf, hash->size + oid_sequence_size));
    RESULT_CHECKED_MEMCPY(hash_oid_buf->data, oid_sequence, oid_sequence_size);
    RESULT_CHECKED_MEMCPY(&hash_oid_buf->data[oid_sequence_size], hash->data, hash->size);

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_sig_to_asn1_sig(struct s2n_blob *out)
{ 
    RESULT_GUARD_PTR(out);

    ECDSA_SIG signature = { 0 };

    uint32_t rlen = out->size / 2;
    uint32_t slen = out->size / 2;

    /* The PKCS #11 formatted ECDSA signature is two large numbers, encoded side by side. We want to convert
     * this to an ASN.1 encoding that our peer in the connection can understand. To do this, we read the 
     * raw integers into a BIGNUM, and load them into the ECDSA_SIG. Once this is done, we can serialize the
     * signature in a DER format. */
    signature.r = BN_bin2bn(out->data, rlen, NULL);
    RESULT_GUARD_PTR(signature.r);

    signature.s = BN_bin2bn(&out->data[rlen], slen, NULL);
    RESULT_GUARD_PTR(signature.s);

    uint8_t *dersig = NULL;

    /* If i2d_ECDSA_SIG reseives a pointer to a NULL pointer, it will allocated the DER encoded 
     * signature for us, and hand over a buffer in temp. */
    int size = i2d_ECDSA_SIG(&signature, &dersig);
    EXPECT_NOT_EQUAL(0, size);
    EXPECT_NOT_NULL(dersig);

    EXPECT_SUCCESS(s2n_realloc(out, size));
    RESULT_CHECKED_MEMCPY(out->data, dersig, out->size);

    free(dersig);
    BN_clear_free(signature.r);
    BN_clear_free(signature.s);

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_init()
{
    /* A mutex can be specified here, but this integration test is single threaded. */
    PKCS11_GUARD(C_Initialize, NULL);
    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_setup_session(CK_SESSION_HANDLE_PTR session)
{
    RESULT_GUARD_PTR(session);

    CK_ULONG slot_count = 0;
    PKCS11_GUARD(C_GetSlotList, CK_TRUE, NULL, &slot_count);

    CK_SLOT_ID *slot_list = malloc(sizeof(CK_SLOT_ID) * (slot_count));
    RESULT_GUARD_PTR(slot_list);

    PKCS11_GUARD(C_GetSlotList, CK_TRUE, slot_list, &slot_count);
    PKCS11_GUARD(C_OpenSession, 
                 slot_list[pkcs11_test_slot], 
                 CKF_SERIAL_SESSION | CKF_RW_SESSION,
                 NULL,
                 NULL, 
                 session);
    free(slot_list);

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_login(CK_SESSION_HANDLE session, CK_UTF8CHAR *pin, CK_ULONG pin_size)
{
    RESULT_GUARD_PTR(pin);
    EXPECT_NOT_EQUAL(CK_INVALID_HANDLE, session);

    PKCS11_GUARD(C_Login, session, CKU_USER, pin, pin_size);
    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_find_key(CK_SESSION_HANDLE session, const char *label, CK_ULONG label_size, CK_OBJECT_HANDLE_PTR key)
{
    RESULT_GUARD_PTR(label);
    RESULT_GUARD_PTR(key);
    EXPECT_NOT_EQUAL(CK_INVALID_HANDLE, session);

    CK_ULONG count = 0;
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;

    CK_ATTRIBUTE template[] = {
        { CKA_LABEL, (CK_VOID_PTR) label, label_size },
        { CKA_CLASS, &key_class, sizeof(CK_OBJECT_CLASS) }
    };

    PKCS11_GUARD(C_FindObjectsInit, session, template, sizeof(template) / sizeof(CK_ATTRIBUTE));

    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    PKCS11_GUARD(C_FindObjects, session, &handle, 1UL, &count);
    PKCS11_GUARD(C_FindObjectsFinal, session);

    EXPECT_TRUE(handle != CK_INVALID_HANDLE);
    EXPECT_TRUE(count != 0);

    *key = handle;

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_setup(CK_SESSION_HANDLE_PTR session)
{
    RESULT_GUARD_PTR(session);

    RESULT_GUARD(pkcs11_init());
    RESULT_GUARD(pkcs11_setup_session(session));
    RESULT_GUARD(pkcs11_login(*session, (CK_UTF8CHAR_PTR)pkcs11_pin, sizeof(pkcs11_pin)-1UL));

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_cleanup(CK_SESSION_HANDLE session)
{
    EXPECT_NOT_EQUAL(CK_INVALID_HANDLE, session);

    PKCS11_GUARD(C_CloseSession, session);
    PKCS11_GUARD(C_Finalize, NULL);

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_decrypt_helper(CK_OBJECT_HANDLE key,
                  struct s2n_blob *in,
                  struct s2n_blob *out,
                  CK_MECHANISM mechanism)
{
    RESULT_ENSURE_REF(in);
    RESULT_ENSURE_REF(out);
    EXPECT_NOT_EQUAL(CK_INVALID_HANDLE, key);

    PKCS11_GUARD(C_DecryptInit, session, &mechanism, key);

    CK_ULONG out_len = 0;
    PKCS11_GUARD(C_Decrypt, 
                 session,
                 (CK_BYTE_PTR)in->data,
                 in->size,
                 NULL,
                 &out_len);
    EXPECT_SUCCESS(s2n_alloc(out, out_len));

    PKCS11_GUARD(C_Decrypt, 
                 session,
                 (CK_BYTE_PTR)in->data,
                 in->size,
                 out->data,
                 &out_len);

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_decrypt_rsa(CK_OBJECT_HANDLE key,
                  struct s2n_blob *in,
                  struct s2n_blob *out)
{
    RESULT_GUARD_PTR(in);
    RESULT_GUARD_PTR(out);
    EXPECT_NOT_EQUAL(CK_INVALID_HANDLE, key);

    CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL, 0 };
    EXPECT_OK(pkcs11_decrypt_helper(key, in, out, mechanism));

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_decrypt_ecdsa(CK_OBJECT_HANDLE key,
                  struct s2n_blob *in,
                  struct s2n_blob *out)
{
    RESULT_GUARD_PTR(in);
    RESULT_GUARD_PTR(out);
    EXPECT_NOT_EQUAL(CK_INVALID_HANDLE, key);

    CK_MECHANISM mechanism = { CKM_ECDSA, NULL, 0 };
    EXPECT_OK(pkcs11_decrypt_helper(key, in, out, mechanism));

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_decrypt(CK_OBJECT_HANDLE key,
                  struct s2n_blob *in,
                  struct s2n_blob *out)
{
    RESULT_GUARD_PTR(in);
    RESULT_GUARD_PTR(out);
    EXPECT_NOT_EQUAL(CK_INVALID_HANDLE, key);

    CK_KEY_TYPE keytype = 0;
    CK_ATTRIBUTE template = { CKA_KEY_TYPE, &keytype, sizeof(keytype) };

    PKCS11_GUARD(C_GetAttributeValue, session, key, &template, 1);

    if (keytype == CKK_RSA)
    {
        EXPECT_OK(pkcs11_decrypt_rsa(key, in, out));
    } else {
        EXPECT_OK(pkcs11_decrypt_ecdsa(key, in, out));
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_sign_helper(CK_OBJECT_HANDLE key,
                  struct s2n_blob *in,
                  struct s2n_blob *out,
                  CK_MECHANISM mechanism)
{
    RESULT_ENSURE_REF(in);
    RESULT_ENSURE_REF(out);
    RESULT_ENSURE_NE(CK_INVALID_HANDLE, key);

    PKCS11_GUARD(C_SignInit, session, &mechanism, key);

    CK_ULONG sig_len = 0;
    PKCS11_GUARD(C_Sign,
                 session,
                 in->data,
                 in->size,
                 NULL,
                 &sig_len);

    EXPECT_SUCCESS(s2n_alloc(out, sig_len));

    PKCS11_GUARD(C_Sign, 
                 session,
                 in->data,
                 in->size,
                 out->data,
                 &sig_len);

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_sign_ecdsa(CK_OBJECT_HANDLE key,
                  struct s2n_blob *in,
                  struct s2n_blob *out)
{
    EXPECT_NOT_NULL(in);
    EXPECT_NOT_NULL(out);
    EXPECT_NOT_EQUAL(CK_INVALID_HANDLE, key);

    CK_MECHANISM mechanism = { CKM_ECDSA, NULL, 0 };

    EXPECT_OK(pkcs11_sign_helper(key, in, out, mechanism));
    EXPECT_OK(pkcs11_sig_to_asn1_sig(out));

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_sign_rsa(CK_OBJECT_HANDLE key,
                  struct s2n_blob *in,
                  struct s2n_blob *out,
                  s2n_tls_hash_algorithm hash_type)
{
    EXPECT_NOT_NULL(in);
    EXPECT_NOT_NULL(out);
    EXPECT_NOT_EQUAL(CK_INVALID_HANDLE, key);

    CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL, 0 };

    DEFER_CLEANUP(struct s2n_blob hash_copy = { 0 }, s2n_free);
    EXPECT_OK(prepend_id(hash_type, in, &hash_copy));
    EXPECT_OK(pkcs11_sign_helper(key, &hash_copy, out, mechanism));

    return S2N_RESULT_OK;
}

static S2N_RESULT pkcs11_sign(CK_OBJECT_HANDLE key,
                  struct s2n_blob *in,
                  struct s2n_blob *out,
                  s2n_tls_hash_algorithm hash_type)
{
    RESULT_GUARD_PTR(in);
    RESULT_GUARD_PTR(out);

    CK_KEY_TYPE keytype = 0;
    CK_ATTRIBUTE template = { CKA_KEY_TYPE, &keytype, sizeof(keytype) };

    PKCS11_GUARD(C_GetAttributeValue, session, key, &template, 1);

    if (keytype == CKK_RSA)
    {
        EXPECT_OK(pkcs11_sign_rsa(key, in, out, hash_type));
    } else {
        EXPECT_OK(pkcs11_sign_ecdsa(key, in, out));
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT get_handshake_hash_alg(struct s2n_connection *conn, s2n_tls_hash_algorithm *alg)
{
    RESULT_GUARD_PTR(conn);
    RESULT_GUARD_PTR(alg);

    /* Try client cert object for the hash alg first, since this integration does mutual auth. If it is none, we will try the 
     * regular connection object for the hash algorithm, since this test is re-using functions for both the 
     * server and client. */
    s2n_mode *type = NULL;
    type = s2n_connection_get_ctx(conn);
    EXPECT_NOT_NULL(type);

    if (*type == S2N_CLIENT)
    {
        EXPECT_SUCCESS(s2n_connection_get_selected_client_cert_digest_algorithm(conn, alg));
    } else {
        EXPECT_SUCCESS(s2n_connection_get_selected_digest_algorithm(conn, alg));
    }

    /* Currently there is no ciphersuite that has no hash algorithm. */
    EXPECT_NOT_EQUAL(S2N_TLS_HASH_NONE, *alg);

    return S2N_RESULT_OK;
}

static S2N_RESULT pkey_task_operation(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    EXPECT_NOT_NULL(conn);
    EXPECT_NOT_NULL(op);

    uint32_t input_len;
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input_size(op, &input_len));

    DEFER_CLEANUP(struct s2n_blob input = { 0 }, s2n_free);
    EXPECT_SUCCESS(s2n_alloc(&input, input_len));
    EXPECT_SUCCESS(s2n_async_pkey_op_get_input(op, input.data, input.size));

    s2n_async_pkey_op_type type;
    EXPECT_SUCCESS(s2n_async_pkey_op_get_op_type(op, &type));

    struct s2n_cert_chain_and_key *cert_key = s2n_connection_get_selected_cert(conn);
    EXPECT_NOT_NULL(cert_key);
    CK_SESSION_HANDLE handle = *(CK_SESSION_HANDLE_PTR) s2n_cert_chain_and_key_get_ctx(cert_key);
    EXPECT_NOT_EQUAL(handle, CK_INVALID_HANDLE);

    DEFER_CLEANUP(struct s2n_blob out = { 0 }, s2n_free);

    if (type == S2N_ASYNC_DECRYPT) {
        EXPECT_OK(pkcs11_decrypt(handle, &input, &out));
    } else {
        s2n_tls_hash_algorithm alg = S2N_TLS_HASH_NONE;
        EXPECT_OK(get_handshake_hash_alg(conn, &alg));
        EXPECT_OK(pkcs11_sign(handle, &input, &out, alg));
    }

    EXPECT_SUCCESS(s2n_async_pkey_op_set_output(op, out.data, out.size));
    EXPECT_SUCCESS(s2n_async_pkey_op_apply(op, conn));
    EXPECT_SUCCESS(s2n_async_pkey_op_free(op));

    return S2N_RESULT_OK;
}

static int async_pkey_callback(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    EXPECT_NOT_NULL(conn);
    EXPECT_NOT_NULL(op);

    pkey_conn = conn; 
    pkey_op = op; 

    return S2N_SUCCESS;
}

static int s2n_test_negotiate_with_async_pkey_op(struct s2n_connection *conn, s2n_blocked_status *block) 
{
    int rc = s2n_negotiate(conn, block);
    if (!(rc == 0 || (*block && s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED))) {
        return S2N_FAILURE;
    }

    if (*block == S2N_BLOCKED_ON_APPLICATION_INPUT && pkey_op != NULL) {
        EXPECT_OK(pkey_task_operation(pkey_conn, pkey_op));
        pkey_op = NULL;
        pkey_conn = NULL;
    }

    return S2N_SUCCESS;
}

static int s2n_try_handshake_with_async_pkey_op(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    s2n_blocked_status server_blocked = { 0 };
    s2n_blocked_status client_blocked = { 0 };

    do {
        EXPECT_SUCCESS(s2n_test_negotiate_with_async_pkey_op(client_conn, &client_blocked));
        EXPECT_SUCCESS(s2n_test_negotiate_with_async_pkey_op(server_conn, &server_blocked));
    } while (client_blocked || server_blocked);

    POSIX_GUARD(s2n_shutdown_test_server_and_client(server_conn, client_conn));

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_cert_chain_and_key *ecdsa_chain_and_key;
    char ecdsa_cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];

    POSIX_GUARD(s2n_read_test_pem(S2N_ECDSA_P256_PKCS1_CERT_CHAIN, ecdsa_cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));

    POSIX_GUARD_PTR(ecdsa_chain_and_key = s2n_cert_chain_and_key_new());
    POSIX_GUARD(s2n_cert_chain_and_key_set_cert_chain_bytes(ecdsa_chain_and_key, (uint8_t*)ecdsa_cert_chain_pem, strlen(ecdsa_cert_chain_pem)));
    POSIX_GUARD(s2n_cert_chain_and_key_load(ecdsa_chain_and_key));

    CK_OBJECT_HANDLE ecdsa_handle = CK_INVALID_HANDLE;

    EXPECT_OK(pkcs11_setup(&session));
    EXPECT_OK(pkcs11_find_key(session, pkcs11_ecdsa_key_label, sizeof(pkcs11_ecdsa_key_label)-1, &ecdsa_handle));

    POSIX_GUARD(s2n_cert_chain_and_key_set_ctx(ecdsa_chain_and_key, &ecdsa_handle));

    /*  Test: ECDSA */
    {
        struct s2n_config *config;

        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(config, async_pkey_callback));

        /* Using this configuration as it allows for ECDSA cipher suites. */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20190214"));

        s2n_mode client = S2N_CLIENT;
        struct s2n_connection *client_conn = s2n_connection_new(client);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        EXPECT_SUCCESS(s2n_connection_set_ctx(client_conn, &client));

        s2n_mode server = S2N_SERVER;
        struct s2n_connection *server_conn = s2n_connection_new(server);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        EXPECT_SUCCESS(s2n_connection_set_ctx(server_conn, &server));

        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_try_handshake_with_async_pkey_op(server_conn, client_conn));

        /* Free the data */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_chain_and_key));

    struct s2n_cert_chain_and_key *rsa_chain_and_key;

    char rsa_cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
    POSIX_GUARD(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, rsa_cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));

    POSIX_GUARD_PTR(rsa_chain_and_key = s2n_cert_chain_and_key_new());
    POSIX_GUARD(s2n_cert_chain_and_key_set_cert_chain_bytes(rsa_chain_and_key, (uint8_t*)rsa_cert_chain_pem, strlen(rsa_cert_chain_pem)));
    POSIX_GUARD(s2n_cert_chain_and_key_load(rsa_chain_and_key));

    CK_OBJECT_HANDLE rsa_handle = CK_INVALID_HANDLE;
    EXPECT_OK(pkcs11_find_key(session, pkcs11_rsa_key_label, sizeof(pkcs11_rsa_key_label)-1, &rsa_handle));
    POSIX_GUARD(s2n_cert_chain_and_key_set_ctx(rsa_chain_and_key, &rsa_handle));

    /*  Test: RSA */
    {
        struct s2n_config *config;

        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(config, async_pkey_callback));

        s2n_mode client = S2N_CLIENT;
        struct s2n_connection *client_conn = s2n_connection_new(client);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        EXPECT_SUCCESS(s2n_connection_set_ctx(client_conn, &client));

        s2n_mode server = S2N_SERVER;
        struct s2n_connection *server_conn = s2n_connection_new(server);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        EXPECT_SUCCESS(s2n_connection_set_ctx(server_conn, &server));

        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_try_handshake_with_async_pkey_op(server_conn, client_conn));

        /* Free the data */
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(config));

    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_chain_and_key));
    EXPECT_OK(pkcs11_cleanup(session));

    END_TEST();
    return 0;
}

