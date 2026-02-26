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

static S2N_RESULT s2n_test_pem_paths_from_intent_dir(const char *intent_cert_dir, char *cert_chain_path,
        char *leaf_key_path, char *root_cert_path)
{
    sprintf(cert_chain_path, "%s/cert-chain.pem", intent_cert_dir);
    sprintf(leaf_key_path, "%s/leaf-key.pem", intent_cert_dir);
    sprintf(root_cert_path, "%s/root-cert.pem", intent_cert_dir);
    return S2N_RESULT_OK;
}

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    /* Test s2n_config_disable_x509_intent_verification(). */
    {
        /* Safety */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_disable_x509_intent_verification(NULL), S2N_ERR_INVALID_ARGUMENT);

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_disable_x509_intent_verification(config));
        }

        /* The verification is enabled by default. */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            EXPECT_FALSE(config->disable_x509_intent_verification);
        }

        /* Disabling the verification on the config updates the proper flags. */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);

            EXPECT_FALSE(config->disable_x509_intent_verification);
            EXPECT_SUCCESS(s2n_config_disable_x509_intent_verification(config));
            EXPECT_TRUE(config->disable_x509_intent_verification);
        }
    }

    /* Test certificate intent verification. */
    {
        struct {
            const char *cert_chain_dir;
            s2n_error expected_client_error;
            s2n_error expected_server_error;
        } test_cases[] = {
            {
                    /* A certificate chain with no optional intent extensions specified. This
                     * certificate chain includes the mandatory BasicConstraints extension for CA
                     * certificates, but doesn't include the KeyUsage or ExtendedKeyUsage
                     * extensions.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/no_intent",
                    /* The KeyUsage and ExtendedKeyUsage extensions are optional, so validation
                     * should succeed.
                     */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with digitalSignature set in the leaf KeyUsage
                     * extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/ku_digital_signature_leaf",
                    /* Setting digitalSignature is valid for both client and server leaf
                     * certificates.
                     */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_OK,
            },
#if !defined(LIBRESSL_VERSION_NUMBER)
            /* This test is skipped for LibreSSL since LibreSSL doesn't consider keyAgreement to be
             * valid for client or server leaf certificates:
             * https://github.com/libressl/openbsd/blob/8bb14039f52469491bf0058b1efdf0c75db6befc/src/lib/libcrypto/x509/x509_purp.c#L662-L691
             */
            {
                    /* A certificate chain with keyAgreement set in the leaf KeyUsage extension. */
                    .cert_chain_dir = "../pems/intent/cert_chains/ku_key_agreement_leaf",
                    /* Setting keyAgreement is valid for both client and server leaf certificates. */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_OK,
            },
#endif
            {
                    /* A certificate chain with digitalSignature and keyAgreement set in the leaf
                     * KeyUsage extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/ku_digital_signature_and_key_agreement_leaf",
                    /* Setting digitalSignature OR keyAgreement is valid for both client and server
                     * leaf certificates. Setting both fields is also valid.
                     */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with digitalSignature and contentCommitment set in the leaf
                     * KeyUsage extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/ku_digital_signature_and_content_commitment_leaf",
                    /* Setting digitalSignature is valid for both client and server leaf
                     * certificates. contentCommitment is not relevant for client or server
                     * certificates, but since digitalSignature is set, validation should succeed.
                     */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with keyEncipherment set in the leaf KeyUsage extension. */
                    .cert_chain_dir = "../pems/intent/cert_chains/ku_key_encipherment_leaf",
                    /* Setting keyEncipherment is valid for server leaf certificates, but is NOT
                     * valid for client leaf certificates.
                     */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_CERT_INTENT_INVALID,
            },
            {
                    /* A certificate chain with keyCertSign set in the leaf KeyUsage extension. */
                    .cert_chain_dir = "../pems/intent/cert_chains/ku_key_cert_sign_leaf",
                    /* Setting keyCertSign is only valid for CA certificates, NOT for leaf
                     * certificates.
                     */
                    .expected_client_error = S2N_ERR_CERT_INTENT_INVALID,
                    .expected_server_error = S2N_ERR_CERT_INTENT_INVALID,
            },
            {
                    /* A certificate chain with keyCertSign set in an intermediate KeyUsage
                     * extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/ku_key_cert_sign_intermediate",
                    /* Setting keyCertSign is valid for CA certificates. */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with keyCertSign and contentCommitment set in an
                     * intermediate KeyUsage extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/ku_key_cert_sign_and_content_commitment_intermediate",
                    /* Setting keyCertSign is valid for CA certificates. The irrelevant
                     * contentCommitment field should not impact validation.
                     */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with clientAuth and serverAuth set in the leaf
                     * ExtendedKeyUsage extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/eku_clientAuth_and_serverAuth_leaf",
                    /* A certificate that sets both clientAuth and serverAuth is valid for both
                     * client and server certificates.
                     */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with clientAuth and serverAuth set in an intermediate
                     * ExtendedKeyUsage extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/eku_clientAuth_and_serverAuth_intermediate",
                    /* A certificate that sets both clientAuth and serverAuth is valid for both
                     * client and server certificates.
                     */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with clientAuth, serverAuth, and emailProtection set in
                     * the leaf ExtendedKeyUsage extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/eku_clientAuth_and_serverAuth_and_emailProtection_leaf",
                    /* A certificate that sets both clientAuth and serverAuth is valid for both
                     * client and server certificates. The irrelevant emailProtection field should
                     * not impact validation.
                     */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with clientAuth, serverAuth, and emailProtection set in
                     * an intermediate ExtendedKeyUsage extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/eku_clientAuth_and_serverAuth_and_emailProtection_intermediate",
                    /* A certificate that sets both clientAuth and serverAuth is valid for both
                     * client and server certificates. The irrelevant emailProtection field should
                     * not impact validation.
                     */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with clientAuth set in the leaf ExtendedKeyUsage
                     * extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/eku_clientAuth_leaf",
                    /* A certificate that sets clientAuth is valid for client certificates, but NOT
                     * for server certificates.
                     */
                    .expected_client_error = S2N_ERR_CERT_INTENT_INVALID,
                    .expected_server_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with clientAuth set in an intermediate ExtendedKeyUsage
                     * extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/eku_clientAuth_intermediate",
                    /* A certificate that sets clientAuth is valid for client certificates, but NOT
                     * for server certificates.
                     */
                    .expected_client_error = S2N_ERR_CERT_INTENT_INVALID,
                    .expected_server_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with serverAuth set in the leaf ExtendedKeyUsage
                     * extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/eku_serverAuth_leaf",
                    /* A certificate that sets serverAuth is valid for server certificates but NOT
                     * for client certificates.
                     */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_CERT_INTENT_INVALID,
            },
            {
                    /* A certificate chain with serverAuth set in an intermediate ExtendedKeyUsage
                     * extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/eku_serverAuth_intermediate",
                    /* A certificate that sets serverAuth is valid for server certificates but NOT
                     * for client certificates.
                     */
                    .expected_client_error = S2N_ERR_OK,
                    .expected_server_error = S2N_ERR_CERT_INTENT_INVALID,
            },
            {
                    /* A certificate chain with codeSigning in the leaf ExtendedKeyUsage extension. */
                    .cert_chain_dir = "../pems/intent/cert_chains/eku_codeSigning_leaf",
                    /* A certificate that sets codeSigning is NOT valid for client or server
                     * certificates.
                     */
                    .expected_client_error = S2N_ERR_CERT_INTENT_INVALID,
                    .expected_server_error = S2N_ERR_CERT_INTENT_INVALID,
            },
            {
                    /* A certificate chain with codeSigning in an intermediate ExtendedKeyUsage
                     * extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/eku_codeSigning_intermediate",
                    /* A certificate that sets codeSigning is NOT valid for client or server
                     * certificates.
                     */
                    .expected_client_error = S2N_ERR_CERT_INTENT_INVALID,
                    .expected_server_error = S2N_ERR_CERT_INTENT_INVALID,
            },
            {
                    /* A long certificate chain with codeSigning set in the fourth intermediate
                     * ExtendedKeyUsage extension.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/eku_codeSigning_intermediate_long",
                    /* A certificate that sets codeSigning is NOT valid for client or server
                     * certificates.
                     */
                    .expected_client_error = S2N_ERR_CERT_INTENT_INVALID,
                    .expected_server_error = S2N_ERR_CERT_INTENT_INVALID,
            },
            {
                    /* A certificate chain with crlSign set in the leaf KeyUsage extension, but the
                     * extension is marked as non-critical.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/ku_crl_sign_leaf_non_critical",
                    /* A certificate that sets crlSign is NOT valid for client or server
                     * certificates. This should be validated regardless of the extension
                     * criticality.
                     */
                    .expected_client_error = S2N_ERR_CERT_INTENT_INVALID,
                    .expected_server_error = S2N_ERR_CERT_INTENT_INVALID,
            },
            {
                    /* A certificate chain with codeSigning set in the leaf ExtendedKeyUsage
                     * extension, but the extension is marked as non-critical.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/eku_code_signing_intermediate_non_critical",
                    /* A certificate that sets codeSigning is NOT valid for client or server
                     * certificates. This should be validated regardless of the extension
                     * criticality.
                     */
                    .expected_client_error = S2N_ERR_CERT_INTENT_INVALID,
                    .expected_server_error = S2N_ERR_CERT_INTENT_INVALID,
            },
        };

        for (size_t test_idx = 0; test_idx < s2n_array_len(test_cases); test_idx++) {
            char cert_chain_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
            char leaf_key_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
            char root_cert_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
            EXPECT_OK(s2n_test_pem_paths_from_intent_dir(test_cases[test_idx].cert_chain_dir, cert_chain_path,
                    leaf_key_path, root_cert_path));

            /* Intent is verified for server certificates received by the client. */
            for (size_t disable_intent_verification = 0; disable_intent_verification <= 1; disable_intent_verification++) {
                DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
                EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                        cert_chain_path, leaf_key_path));

                DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
                EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, root_cert_path, NULL));
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

                DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

                DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
                EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));
                EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

                if (disable_intent_verification) {
                    EXPECT_SUCCESS(s2n_config_disable_x509_intent_verification(config));
                }

                DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
                EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
                EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
                EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

                int ret = s2n_negotiate_test_server_and_client(server_conn, client_conn);

                s2n_error expected_error = test_cases[test_idx].expected_client_error;
                if (disable_intent_verification) {
                    EXPECT_SUCCESS(ret);
                } else {
                    if (expected_error == S2N_ERR_OK) {
                        EXPECT_SUCCESS(ret);
                    } else {
                        EXPECT_FAILURE_WITH_ERRNO(ret, expected_error);
                    }
                }
            }

            /* Intent is verified for client certificates received by the server. */
            for (size_t disable_intent_verification = 0; disable_intent_verification <= 1; disable_intent_verification++) {
                DEFER_CLEANUP(struct s2n_cert_chain_and_key *server_chain_and_key = NULL,
                        s2n_cert_chain_and_key_ptr_free);
                EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&server_chain_and_key,
                        S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

                DEFER_CLEANUP(struct s2n_cert_chain_and_key *client_chain_and_key = NULL,
                        s2n_cert_chain_and_key_ptr_free);
                EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&client_chain_and_key,
                        cert_chain_path, leaf_key_path));

                DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
                EXPECT_NOT_NULL(server_config);
                EXPECT_SUCCESS(s2n_config_set_verification_ca_location(server_config, root_cert_path, NULL));
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, server_chain_and_key));
                EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_REQUIRED));

                if (disable_intent_verification) {
                    EXPECT_SUCCESS(s2n_config_disable_x509_intent_verification(server_config));
                }

                DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
                EXPECT_NOT_NULL(client_config);
                EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config,
                        S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, client_chain_and_key));
                EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_OPTIONAL));

                DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
                EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

                DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
                EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

                DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
                EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
                EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
                EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

                int ret = s2n_negotiate_test_server_and_client(server_conn, client_conn);

                s2n_error expected_error = test_cases[test_idx].expected_server_error;
                if (disable_intent_verification) {
                    EXPECT_SUCCESS(ret);
                } else {
                    if (expected_error == S2N_ERR_OK) {
                        EXPECT_SUCCESS(ret);
                    } else {
                        EXPECT_FAILURE_WITH_ERRNO(ret, expected_error);
                    }
                }

                /* Ensure that a client certificate was received. In the case of an expected error,
                 * this ensures that the error occurred on the server side, after the client
                 * successfully validated the server's certificate.
                 */
                uint8_t *client_cert_chain = NULL;
                uint32_t client_cert_chain_len = 0;
                EXPECT_SUCCESS(s2n_connection_get_client_cert_chain(server_conn, &client_cert_chain,
                        &client_cert_chain_len));
                EXPECT_TRUE(client_cert_chain_len > 0);
            }
        }
    }

    /* Test default s2n-tls intent verification.
     *
     * s2n-tls already verifies intent fields for intermediate certificates in the call to
     * X509_verify_cert. So this verification should continue to be performed whether certificate
     * intent verification is enabled or not.
     */
    {
        struct {
            const char *cert_chain_dir;
        } test_cases[] = {
            {
                    /* A certificate chain with the CA field set to false in an intermediate
                     * BasicConstraints extension.
                     *
                     * CA certificates MUST set the CA field to true.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/bc_non_ca_intermediate",
            },
            {
                    /* A certificate chain with digitalSignature set in an intermediate KeyUsage
                     * extension.
                     *
                     * The digitalSignature field is valid only for leaf certificates, NOT CA
                     * certificates.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/ku_digital_signature_intermediate",
            },
            {
                    /* A long certificate chain with digitalSignature set in the fourth
                     * intermediate KeyUsage extension.
                     *
                     * The digitalSignature field is valid only for leaf certificates, NOT CA
                     * certificates.
                     */
                    .cert_chain_dir = "../pems/intent/cert_chains/ku_digital_signature_intermediate_long",
            },
        };

        for (size_t test_idx = 0; test_idx < s2n_array_len(test_cases); test_idx++) {
            char cert_chain_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
            char leaf_key_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
            char root_cert_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
            EXPECT_OK(s2n_test_pem_paths_from_intent_dir(test_cases[test_idx].cert_chain_dir, cert_chain_path,
                    leaf_key_path, root_cert_path));

            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, cert_chain_path, leaf_key_path));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, root_cert_path, NULL));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_CERT_UNTRUSTED);
        }
    }

    /* Ensure that intent verification doesn't apply to trust anchors.
     *
     * Despite certificate intent fields that may indicate otherwise, it is assumed that trust
     * anchors were intended to be used for a TLS purpose, given that they were included in the
     * s2n-tls trust store.
     */
    {
        struct {
            const char *cert_chain_path;
            const char *leaf_key_path;
            const char *trust_anchor_path;
            s2n_error expected_error;
        } test_cases[] = {
            {
                    /* A certificate chain with codeSigning in the leaf ExtendedKeyUsage extension. */
                    .cert_chain_path = "../pems/intent/cert_chains/eku_codeSigning_leaf/cert-chain.pem",
                    .leaf_key_path = "../pems/intent/cert_chains/eku_codeSigning_leaf/leaf-key.pem",
                    /* A certificate that sets codeSigning is not valid for TLS. When the invalid
                     * leaf certificate is not a trust anchor, validation should fail.
                     */
                    .trust_anchor_path = "../pems/intent/cert_chains/eku_codeSigning_leaf/root-cert.pem",
                    .expected_error = S2N_ERR_CERT_INTENT_INVALID,
            },
            {
                    /* A certificate chain with codeSigning in the leaf ExtendedKeyUsage extension. */
                    .cert_chain_path = "../pems/intent/cert_chains/eku_codeSigning_leaf/cert-chain.pem",
                    .leaf_key_path = "../pems/intent/cert_chains/eku_codeSigning_leaf/leaf-key.pem",
                    /* A certificate that sets codeSigning is not valid for TLS. However, this is
                     * acceptable if the invalid leaf certificate is a trust anchor.
                     */
                    .trust_anchor_path = "../pems/intent/cert_chains/eku_codeSigning_leaf/leaf-cert.pem",
                    .expected_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with codeSigning in an intermediate ExtendedKeyUsage
                     * extension.
                     */
                    .cert_chain_path = "../pems/intent/cert_chains/eku_codeSigning_intermediate/cert-chain.pem",
                    .leaf_key_path = "../pems/intent/cert_chains/eku_codeSigning_intermediate/leaf-key.pem",
                    /* A certificate that sets codeSigning is not valid for TLS. When the invalid
                     * intermediate certificate is not a trust anchor, validation should fail.
                     */
                    .trust_anchor_path = "../pems/intent/cert_chains/eku_codeSigning_intermediate/root-cert.pem",
                    .expected_error = S2N_ERR_CERT_INTENT_INVALID,
            },
            {
                    /* A certificate chain with codeSigning in an intermediate ExtendedKeyUsage
                     * extension.
                     */
                    .cert_chain_path = "../pems/intent/cert_chains/eku_codeSigning_intermediate/cert-chain.pem",
                    .leaf_key_path = "../pems/intent/cert_chains/eku_codeSigning_intermediate/leaf-key.pem",
                    /* A certificate that sets codeSigning is not valid for TLS. However, this is
                     * acceptable if the invalid intermediate certificate is a trust anchor.
                     */
                    .trust_anchor_path = "../pems/intent/cert_chains/eku_codeSigning_intermediate/intermediate_1-cert.pem",
                    .expected_error = S2N_ERR_OK,
            },
            {
                    /* A certificate chain with codeSigning in an intermediate ExtendedKeyUsage
                     * extension.
                     */
                    .cert_chain_path = "../pems/intent/cert_chains/eku_codeSigning_intermediate/cert-chain.pem",
                    .leaf_key_path = "../pems/intent/cert_chains/eku_codeSigning_intermediate/leaf-key.pem",
                    /* A certificate that sets codeSigning is not valid for TLS. However, this is
                     * acceptable if the leaf certificate is a trust anchor, since the invalid
                     * intermediate certificate won't be in the chain of trust.
                     */
                    .trust_anchor_path = "../pems/intent/cert_chains/eku_codeSigning_intermediate/leaf-cert.pem",
                    .expected_error = S2N_ERR_OK,
            },
            {
                    /* A certificate that sets emailProtection in the root ExtendedKeyUsage extension. */
                    .cert_chain_path = "../pems/intent/cert_chains/eku_email_protection_root/cert-chain.pem",
                    .leaf_key_path = "../pems/intent/cert_chains/eku_email_protection_root/leaf-key.pem",
                    /* A certificate that sets emailProtection is not valid for TLS. However, this is
                     * acceptable if the certificate is a trust anchor.
                     */
                    .trust_anchor_path = "../pems/intent/cert_chains/eku_email_protection_root/root-cert.pem",
                    .expected_error = S2N_ERR_OK,
            },
        };

        for (size_t test_idx = 0; test_idx < s2n_array_len(test_cases); test_idx++) {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    test_cases[test_idx].cert_chain_path, test_cases[test_idx].leaf_key_path));

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                    test_cases[test_idx].trust_anchor_path, NULL));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
            EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

            int ret = s2n_negotiate_test_server_and_client(server_conn, client_conn);

            s2n_error expected_error = test_cases[test_idx].expected_error;
            if (expected_error == S2N_ERR_OK) {
                EXPECT_SUCCESS(ret);
            } else {
                EXPECT_FAILURE_WITH_ERRNO(ret, expected_error);
            }
        }
    }

    END_TEST();
}
