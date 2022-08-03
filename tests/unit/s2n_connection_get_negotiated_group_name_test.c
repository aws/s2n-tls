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

#include "crypto/s2n_fips.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/extensions/s2n_client_server_name.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_internal.h"
#include "tls/s2n_tls.h"

#include "crypto/s2n_hash.h"

#include "utils/s2n_socket.h"
#include "utils/s2n_blob.h"

#if EVP_APIS_SUPPORTED
    #define S2N_X25519_IF_AVAILABLE "x25519"
    #define S2N_X25519_KYBER_R3_IF_AVAILABLE "x25519_kyber-512-r3"
#else
    #define S2N_X25519_IF_AVAILABLE "secp256r1"
#define S2N_X25519_KYBER_R3_IF_AVAILABLE "secp256r1_kyber-512-r3"
#endif

#if S2N_NO_PQ
    #undef S2N_X25519_KYBER_R3_IF_AVAILABLE
    #define S2N_X25519_KYBER_R3_IF_AVAILABLE S2N_X25519_IF_AVAILABLE
    #define S2N_P256_KYBER_R3_IF_AVAILABLE "secp256r1"
#else
    #define S2N_P256_KYBER_R3_IF_AVAILABLE "secp256r1_kyber-512-r3"
#endif

struct negotiated_policy_params {
    const char *policy_name;
    const char *expected_group;
};

/* Must be in the same order as security_policy_selection in tls/s2n_security_policies.c */
struct negotiated_policy_params policy_to_expected_group_name[] = {
        /* Security Policy Name, Negotiated Cipher, Negotiated TLS Version, Negotiated Group */
        {.policy_name="default", .expected_group="secp256r1"},
        {.policy_name="default_tls13", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="default_fips", .expected_group="secp256r1"},
        {.policy_name="ELBSecurityPolicy-TLS-1-0-2015-04", .expected_group="secp256r1"},
        {.policy_name="ELBSecurityPolicy-TLS-1-0-2015-05", .expected_group="secp256r1"},
        {.policy_name="ELBSecurityPolicy-2016-08", .expected_group="secp256r1"},
        {.policy_name="ELBSecurityPolicy-TLS-1-1-2017-01", .expected_group="secp256r1"},
        {.policy_name="ELBSecurityPolicy-TLS-1-2-2017-01", .expected_group="secp256r1"},
        {.policy_name="ELBSecurityPolicy-TLS-1-2-Ext-2018-06", .expected_group="secp256r1"},
        {.policy_name="ELBSecurityPolicy-FS-2018-06", .expected_group="secp256r1"},
        {.policy_name="ELBSecurityPolicy-FS-1-2-2019-08", .expected_group="secp256r1"},
        {.policy_name="ELBSecurityPolicy-FS-1-1-2019-08", .expected_group="secp256r1"},
        {.policy_name="ELBSecurityPolicy-FS-1-2-Res-2019-08", .expected_group="secp256r1"},
        {.policy_name="CloudFront-Upstream", .expected_group="secp256r1"},
        {.policy_name="CloudFront-Upstream-TLS-1-0", .expected_group="secp256r1"},
        {.policy_name="CloudFront-Upstream-TLS-1-1", .expected_group="secp256r1"},
        {.policy_name="CloudFront-Upstream-TLS-1-2", .expected_group="secp256r1"},
        {.policy_name="CloudFront-SSL-v-3", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="CloudFront-TLS-1-0-2014", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="CloudFront-TLS-1-0-2016", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="CloudFront-TLS-1-1-2016", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="CloudFront-TLS-1-2-2018", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="CloudFront-TLS-1-2-2019", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="CloudFront-TLS-1-2-2021", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="CloudFront-SSL-v-3-Legacy", .expected_group="secp256r1"},
        {.policy_name="CloudFront-TLS-1-0-2014-Legacy", .expected_group="secp256r1"},
        {.policy_name="CloudFront-TLS-1-0-2016-Legacy", .expected_group="secp256r1"},
        {.policy_name="CloudFront-TLS-1-1-2016-Legacy", .expected_group="secp256r1"},
        {.policy_name="CloudFront-TLS-1-2-2018-Legacy", .expected_group="secp256r1"},
        {.policy_name="CloudFront-TLS-1-2-2019-Legacy", .expected_group="secp256r1"},
        {.policy_name="AWS-CRT-SDK-SSLv3.0", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="AWS-CRT-SDK-TLSv1.0", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="AWS-CRT-SDK-TLSv1.1", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="AWS-CRT-SDK-TLSv1.2", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="AWS-CRT-SDK-TLSv1.3", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="KMS-TLS-1-0-2018-10", .expected_group="secp256r1"},
        {.policy_name="KMS-TLS-1-0-2021-08", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="KMS-FIPS-TLS-1-2-2018-10", .expected_group="secp256r1"},
        {.policy_name="KMS-FIPS-TLS-1-2-2021-08", .expected_group="secp256r1"},
        {.policy_name="KMS-PQ-TLS-1-0-2019-06", .expected_group="secp256r1"},
        {.policy_name="KMS-PQ-TLS-1-0-2020-02", .expected_group="secp256r1"},
        {.policy_name="KMS-PQ-TLS-1-0-2020-07", .expected_group=S2N_P256_KYBER_R3_IF_AVAILABLE},
        {.policy_name="PQ-SIKE-TEST-TLS-1-0-2019-11", .expected_group="secp256r1"},
        {.policy_name="PQ-SIKE-TEST-TLS-1-0-2020-02", .expected_group="secp256r1"},
        {.policy_name="PQ-TLS-1-0-2020-12", .expected_group=S2N_X25519_KYBER_R3_IF_AVAILABLE},
        {.policy_name="PQ-TLS-1-1-2021-05-17", .expected_group=S2N_X25519_KYBER_R3_IF_AVAILABLE},
        {.policy_name="PQ-TLS-1-0-2021-05-18", .expected_group=S2N_X25519_KYBER_R3_IF_AVAILABLE},
        {.policy_name="PQ-TLS-1-0-2021-05-19", .expected_group=S2N_X25519_KYBER_R3_IF_AVAILABLE},
        {.policy_name="PQ-TLS-1-0-2021-05-20", .expected_group=S2N_X25519_KYBER_R3_IF_AVAILABLE},
        {.policy_name="PQ-TLS-1-1-2021-05-21", .expected_group=S2N_X25519_KYBER_R3_IF_AVAILABLE},
        {.policy_name="PQ-TLS-1-0-2021-05-22", .expected_group=S2N_X25519_KYBER_R3_IF_AVAILABLE},
        {.policy_name="PQ-TLS-1-0-2021-05-23", .expected_group=S2N_X25519_KYBER_R3_IF_AVAILABLE},
        {.policy_name="PQ-TLS-1-0-2021-05-24", .expected_group=S2N_X25519_KYBER_R3_IF_AVAILABLE},
        {.policy_name="PQ-TLS-1-0-2021-05-25", .expected_group=S2N_X25519_KYBER_R3_IF_AVAILABLE},
        {.policy_name="PQ-TLS-1-0-2021-05-26", .expected_group=S2N_X25519_KYBER_R3_IF_AVAILABLE},
        {.policy_name="20140601", .expected_group="NONE"},
        {.policy_name="20141001", .expected_group="NONE"},
        {.policy_name="20150202", .expected_group="NONE"},
        {.policy_name="20150214", .expected_group="NONE"},
        {.policy_name="20150306", .expected_group="secp256r1"},
        {.policy_name="20160411", .expected_group="secp256r1"},
        {.policy_name="20160804", .expected_group="secp256r1"},
        {.policy_name="20160824", .expected_group="secp256r1"},
        {.policy_name="20170210", .expected_group="secp256r1"},
        {.policy_name="20170328", .expected_group="secp256r1"},
        {.policy_name="20170328_gcm", .expected_group="secp256r1"},
        {.policy_name="20190214", .expected_group="secp256r1"},
        {.policy_name="20190214_gcm", .expected_group="secp256r1"},
        {.policy_name="20210825", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="20210825_gcm", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="20170405", .expected_group="secp256r1"},
        {.policy_name="20170405_gcm", .expected_group="secp256r1"},
        {.policy_name="20170718", .expected_group="secp256r1"},
        {.policy_name="20170718_gcm", .expected_group="secp256r1"},
        {.policy_name="20190120", .expected_group="secp256r1"},
        {.policy_name="20190121", .expected_group="secp256r1"},
        {.policy_name="20190122", .expected_group="secp256r1"},
        {.policy_name="20190801", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="20190802", .expected_group="secp256r1"},
        {.policy_name="20200207", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="20201021", .expected_group="secp256r1"},
        {.policy_name="20210816", .expected_group="secp384r1"},
        {.policy_name="20210816_GCM", .expected_group="secp384r1"},
        {.policy_name="test_all", .expected_group=S2N_X25519_KYBER_R3_IF_AVAILABLE},
        {.policy_name="test_all_fips", .expected_group="NONE"},
        {.policy_name="test_all_ecdsa", .expected_group=S2N_X25519_IF_AVAILABLE},
        {.policy_name="test_all_rsa_kex", .expected_group="NONE"},
        {.policy_name="test_ecdsa_priority", .expected_group="NONE"},
        {.policy_name="test_all_tls12", .expected_group="NONE"},
        {.policy_name="test_all_tls13", .expected_group=S2N_X25519_IF_AVAILABLE},
};

bool s2n_str_has_prefix(const char* str, const char* prefix){
    if (strlen(prefix) > strlen(str)) {
        return 0;
    }
    return (strncmp(str, prefix, strlen(prefix)) == 0);
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    struct s2n_cert_chain_and_key *rsa_chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    for (size_t policy_index = 0; security_policy_selection[policy_index].security_policy != &security_policy_null; policy_index++) {
        const struct s2n_security_policy *security_policy = security_policy_selection[policy_index].security_policy;
        const char *security_policy_name = security_policy_selection[policy_index].version;

        if ((s2n_get_highest_fully_supported_tls_version() <= S2N_TLS12)
                && ((security_policy->minimum_protocol_version == S2N_TLS13) || (security_policy == &security_policy_test_all_tls13))) {
            /* We can't negotiate this security policy due to old version of Openssl, so skip it. */
            continue;
        }

        struct s2n_config *config = s2n_config_new();
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        if (security_policy == &security_policy_test_all_ecdsa) {
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_chain_and_key));
        } else {
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_chain_and_key));
        }
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, security_policy_name));

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        const char *client_group_name = s2n_connection_get_negotiated_group_name(client_conn);
        const char *server_group_name = s2n_connection_get_negotiated_group_name(server_conn);


        EXPECT_NOT_NULL(client_group_name);
        EXPECT_NOT_NULL(server_group_name);

        EXPECT_STRING_EQUAL(client_group_name, server_group_name);
        EXPECT_STRING_EQUAL(server_conn->secure.cipher_suite->name, client_conn->secure.cipher_suite->name);
        EXPECT_EQUAL(server_conn->actual_protocol_version, client_conn->actual_protocol_version);

        const char* expected_policy = policy_to_expected_group_name[policy_index].policy_name;
        const char* expected_group = policy_to_expected_group_name[policy_index].expected_group;

        if (s2n_str_has_prefix(security_policy_name, "test_")
                && !s2n_str_has_prefix(security_policy_name, "test_all_ecdsa")
                && s2n_get_highest_fully_supported_tls_version() <= S2N_TLS12) {
            /* The "test_*" policies have their cipher preferences ordered by IANA value rather than by security
             * strength, leading to them negotiating the old ciphers without ECC support when TLS 1.3 is not available.
             */
            expected_group = "NONE";
        }

        if (s2n_is_in_fips_mode() && !s2n_libcrypto_is_awslc()) {
            /* We only allow PQ in FIPS mode with AWS-LC */
            if (s2n_str_has_prefix(expected_group, "x25519_kyber-512-r3")){
                expected_group = "x25519";
            }
            if (s2n_str_has_prefix(expected_group, "secp256r1_kyber-512-r3")){
                expected_group = "secp256r1";
            }
        }

        EXPECT_STRING_EQUAL(expected_policy, security_policy_name);
        EXPECT_STRING_EQUAL(expected_group, server_group_name);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_chain_and_key));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_chain_and_key));

    END_TEST();
}
