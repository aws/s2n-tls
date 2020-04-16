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

#include <s2n.h>

#include "tls/s2n_security_policies.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_kem_preferences.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"

const struct s2n_security_policy security_policy_20170210= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20170210,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20190801= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20190801,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20170405= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20170405,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_elb_2015_04= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &elb_security_policy_2015_04,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_elb_2016_08= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &elb_security_policy_2015_04,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_elb_tls_1_1_2017_01= {
    .minimum_protocol_version = S2N_TLS11,  
    .cipher_preferences = &elb_security_policy_tls_1_1_2017_01,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_elb_tls_1_2_2017_01= {
    .minimum_protocol_version = S2N_TLS12,  
    .cipher_preferences = &elb_security_policy_tls_1_2_2017_01,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_elb_tls_1_2_ext_2018_06= {
    .minimum_protocol_version = S2N_TLS12,  
    .cipher_preferences = &elb_security_policy_tls_1_2_ext_2018_06,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_elb_fs_2018_06= {
    .minimum_protocol_version = S2N_TLS12,  
    .cipher_preferences = &elb_security_policy_fs_2018_06,
    .kem_preferences = &kem_preferences_null,
};


const struct s2n_security_policy security_policy_elb_fs_1_2_2019_08= {
    .minimum_protocol_version = S2N_TLS12,  
    .cipher_preferences = &elb_security_policy_fs_1_2_2019_08,
    .kem_preferences = &kem_preferences_null,
};


const struct s2n_security_policy security_policy_elb_fs_1_1_2019_08= {
    .minimum_protocol_version = S2N_TLS11,  
    .cipher_preferences = &elb_security_policy_fs_1_1_2019_08,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_elb_fs_1_2_Res_2019_08= {
    .minimum_protocol_version = S2N_TLS12,  
    .cipher_preferences = &elb_security_policy_fs_1_2_Res_2019_08,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_cloudfront_upstream= {
    .minimum_protocol_version = S2N_SSLv3,  
    .cipher_preferences = &cipher_preferences_cloudfront_upstream,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_cloudfront_upstream_tls11= {
    .minimum_protocol_version = S2N_TLS11,  
    .cipher_preferences = &cipher_preferences_cloudfront_upstream_tls11,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_cloudfront_upstream_tls12= {
    .minimum_protocol_version = S2N_TLS12,  
    .cipher_preferences = &cipher_preferences_cloudfront_upstream_tls12,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_cloudfront_ssl_v_3= {
    .minimum_protocol_version = S2N_SSLv3,  
    .cipher_preferences = &cipher_preferences_cloudfront_ssl_v_3,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_cloudfront_tls_1_0_2014= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_cloudfront_tls_1_0_2014,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_cloudfront_tls_1_0_2016= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_cloudfront_tls_1_0_2016,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_cloudfront_tls_1_1_2016 = {
    .minimum_protocol_version = S2N_TLS11,  
    .cipher_preferences = &cipher_preferences_cloudfront_tls_1_1_2016,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2018= {
    .minimum_protocol_version = S2N_TLS12,  
    .cipher_preferences = &cipher_preferences_cloudfront_tls_1_2_2018,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2019= {
    .minimum_protocol_version = S2N_TLS12,  
    .cipher_preferences = &cipher_preferences_cloudfront_tls_1_2_2019,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2020= {
    .minimum_protocol_version = S2N_TLS12,  
    .cipher_preferences = &cipher_preferences_cloudfront_tls_1_2_2020,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_kms_tls_1_0_2018_10= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_kms_tls_1_0_2018_10,
    .kem_preferences = &kem_preferences_null,
};

#if !defined(S2N_NO_PQ)

const struct s2n_security_policy security_policy_kms_pq_tls_1_0_2019_06= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_kms_pq_tls_1_0_2019_06,
    .kem_preferences = &kem_preferences_kms_pq_tls_1_0_2019_06,
};

const struct s2n_security_policy security_policy_kms_pq_tls_1_0_2020_02= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_kms_pq_tls_1_0_2020_02,
    .kem_preferences = &kem_preferences_kms_pq_tls_1_0_2020_02,
};

const struct s2n_security_policy security_policy_pq_sike_test_tls_1_0_2019_11= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_pq_sike_test_tls_1_0_2019_11,
    .kem_preferences = &kem_preferences_pq_sike_test_tls_1_0_2019_11,
};

const struct s2n_security_policy security_policy_pq_sike_test_tls_1_0_2020_02= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_pq_sike_test_tls_1_0_2020_02,
    .kem_preferences = &kem_preferences_pq_sike_test_tls_1_0_2020_02,
};

#endif
const struct s2n_security_policy security_policy_kms_fips_tls_1_2_2018_10= {
    .minimum_protocol_version = S2N_TLS12,  
    .cipher_preferences = &cipher_preferences_kms_fips_tls_1_2_2018_10,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20140601= {
    .minimum_protocol_version = S2N_SSLv3,  
    .cipher_preferences = &cipher_preferences_20140601,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20141001= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20141001,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20150202= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20150202,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20150214= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20150214,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20160411= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20160411,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20150306= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20150306,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20160804= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20160804,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20160824= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20160824,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20190122= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20190122,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20190121= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20190121,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20190120= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20190120,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20190214= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20190214,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20170328= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20170328,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_20170718= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_20170718,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_test_all= {
    .minimum_protocol_version = S2N_SSLv3,  
    .cipher_preferences = &cipher_preferences_test_all,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_test_all_tls12= {
    .minimum_protocol_version = S2N_SSLv3,  
    .cipher_preferences = &cipher_preferences_test_all_tls12,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_test_all_fips= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_test_all_fips,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_test_all_ecdsa= {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_test_all_ecdsa,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_test_all_rsa_kex = {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_test_all_rsa_kex,
    .kem_preferences = &kem_preferences_null,
};

const struct s2n_security_policy security_policy_test_all_tls13 = {
    .minimum_protocol_version = S2N_SSLv3,  
    .cipher_preferences = &cipher_preferences_test_all_rsa_kex,
    .kem_preferences = &kem_preferences_null,
};

struct {
    const char *version;
    const struct s2n_security_policy *security_policy;
} security_policy_selection[] = {
    { .version="default", .security_policy=&security_policy_20170210},
    { .version="default_tls13", .security_policy=&security_policy_20190801},
    { .version="default_fips", .security_policy=&security_policy_20170405},
    { .version="ELBSecurityPolicy-TLS-1-0-2015-04", .security_policy=&security_policy_elb_2015_04},
    /* Not a mistake. TLS-1-0-2015-05 and 2016-08 are equivalent */
    { .version="ELBSecurityPolicy-TLS-1-0-2015-05", .security_policy=&security_policy_elb_2016_08},
    { .version="ELBSecurityPolicy-2016-08", .security_policy=&security_policy_elb_2016_08},
    { .version="ELBSecurityPolicy-TLS-1-1-2017-01", .security_policy=&security_policy_elb_tls_1_1_2017_01},
    { .version="ELBSecurityPolicy-TLS-1-2-2017-01", .security_policy=&security_policy_elb_tls_1_2_2017_01},
    { .version="ELBSecurityPolicy-TLS-1-2-Ext-2018-06", .security_policy=&security_policy_elb_tls_1_2_ext_2018_06},
    { .version="ELBSecurityPolicy-FS-2018-06", .security_policy=&security_policy_elb_fs_2018_06},
    { .version="ELBSecurityPolicy-FS-1-2-2019-08", .security_policy=&security_policy_elb_fs_1_2_2019_08}, 
    { .version="ELBSecurityPolicy-FS-1-1-2019-08", .security_policy=&security_policy_elb_fs_1_1_2019_08}, 
    { .version="ELBSecurityPolicy-FS-1-2-Res-2019-08", .security_policy=&security_policy_elb_fs_1_2_Res_2019_08}, 
    { .version="CloudFront-Upstream", .security_policy=&security_policy_cloudfront_upstream},
    { .version="CloudFront-Upstream-TLS-1-0", .security_policy=&security_policy_cloudfront_upstream_tls10},
    { .version="CloudFront-Upstream-TLS-1-1", .security_policy=&security_policy_cloudfront_upstream_tls11},
    { .version="CloudFront-Upstream-TLS-1-2", .security_policy=&security_policy_cloudfront_upstream_tls12},
    { .version="CloudFront-SSL-v-3", .security_policy=&security_policy_cloudfront_ssl_v_3},
    { .version="CloudFront-TLS-1-0-2014", .security_policy=&security_policy_cloudfront_tls_1_0_2014},
    { .version="CloudFront-TLS-1-0-2016", .security_policy=&security_policy_cloudfront_tls_1_0_2016},
    { .version="CloudFront-TLS-1-1-2016", .security_policy=&security_policy_cloudfront_tls_1_1_2016},
    { .version="CloudFront-TLS-1-2-2018", .security_policy=&security_policy_cloudfront_tls_1_2_2018},
    { .version="CloudFront-TLS-1-2-2019", .security_policy=&security_policy_cloudfront_tls_1_2_2019},
    { .version="CloudFront-TLS-1-2-2020", .security_policy=&security_policy_cloudfront_tls_1_2_2020},
    { .version="KMS-TLS-1-0-2018-10", .security_policy=&security_policy_kms_tls_1_0_2018_10},
#if !defined(S2N_NO_PQ)
    { .version="KMS-PQ-TLS-1-0-2019-06", .security_policy=&security_policy_kms_pq_tls_1_0_2019_06},
    { .version="KMS-PQ-TLS-1-0-2020-02", .security_policy=&security_policy_kms_pq_tls_1_0_2020_02},
    { .version="PQ-SIKE-TEST-TLS-1-0-2019-11", .security_policy=&security_policy_pq_sike_test_tls_1_0_2019_11},
    { .version="PQ-SIKE-TEST-TLS-1-0-2020-02", .security_policy=&security_policy_pq_sike_test_tls_1_0_2020_02},
#endif
    { .version="KMS-FIPS-TLS-1-2-2018-10", .security_policy=&security_policy_kms_fips_tls_1_2_2018_10},
    { .version="20140601", .security_policy=&security_policy_20140601},
    { .version="20141001", .security_policy=&security_policy_20141001},
    { .version="20150202", .security_policy=&security_policy_20150202},
    { .version="20150214", .security_policy=&security_policy_20150214},
    { .version="20150306", .security_policy=&security_policy_20150306},
    { .version="20160411", .security_policy=&security_policy_20160411},
    { .version="20160804", .security_policy=&security_policy_20160804},
    { .version="20160824", .security_policy=&security_policy_20160824},
    { .version="20170210", .security_policy=&security_policy_20170210},
    { .version="20170328", .security_policy=&security_policy_20170328},
    { .version="20190214", .security_policy=&security_policy_20190214},
    { .version="20170405", .security_policy=&security_policy_20170405},
    { .version="20170718", .security_policy=&security_policy_20170718},
    { .version="20190120", .security_policy=&security_policy_20190120},
    { .version="20190121", .security_policy=&security_policy_20190121},
    { .version="20190122", .security_policy=&security_policy_20190122},
    { .version="test_all", .security_policy=&security_policy_test_all},
    { .version="test_all_fips", .security_policy=&security_policy_test_all_fips},
    { .version="test_all_ecdsa", .security_policy=&security_policy_test_all_ecdsa},
    { .version="test_all_rsa_kex", .security_policy=&security_policy_test_all_rsa_kex},
    { .version="test_ecdsa_priority", .security_policy=&security_policy_test_ecdsa_priority},
    { .version="test_all_tls13", .security_policy=&security_policy_test_all_tls13},
    { .version=NULL, .security_policy=NULL}
};


int s2n_find_security_policy_from_version(const char *version, const struct s2n_security_policy **security_policy)
{
    notnull_check(version);
    notnull_check(security_policy);

    for (int i = 0; security_policy_selection[i].version != NULL; i++) {
        if (!strcasecmp(version, security_policy_selection[i].version)) {
            *security_policy = security_policy_selection[i].security_policy;
            return S2N_SUCCESS;
        }
    }

    S2N_ERROR(S2N_ERR_INVALID_SECURITY_POLICY);
}

int s2n_config_set_cipher_preferences(struct s2n_config *config, const char *version)
{
    GUARD(s2n_find_security_policy_from_version(version, &config->security_policy));
    return 0;
}

int s2n_connection_set_cipher_preferences(struct s2n_connection *conn, const char *version)
{
    GUARD(s2n_find_security_policy_from_version(version, &conn->security_policy_override));
    return 0;
}

int s2n_connection_is_valid_for_cipher_preferences(struct s2n_connection *conn, const char *version)
{
    notnull_check(conn);
    notnull_check(version);
    notnull_check(conn->secure.cipher_suite);

    const struct s2n_security_policy *security_policy;
    GUARD(s2n_find_security_policy_from_version(version, &security_policy));

    /* make sure we dont use a tls version lower than that configured by the version */
    if (s2n_connection_get_actual_protocol_version(conn) < security_policy->minimum_protocol_version) {
        return 0;
    }

    struct s2n_cipher_suite *cipher = conn->secure.cipher_suite;
    for (int i = 0; i < security_policy->cipher_preferences->count; ++i) {
        if (0 == memcmp(security_policy->cipher_preferences->suites[i]->iana_value, cipher->iana_value, S2N_TLS_CIPHER_SUITE_LEN)) {
            return 1;
        }
    }
    return 0;
}

int s2n_ecc_is_extension_required(const struct s2n_security_policy *security_policy)
{
    notnull_check(security_policy);
    notnull_check(security_policy->cipher_preferences);
    const struct s2n_cipher_preferences *cipher_preferences = security_policy->cipher_preferences;
    for (int i = 0; i < cipher_preferences->count; i++) {
        struct s2n_cipher_suite *cipher = cipher_preferences->suites[i];
        /* TLS1.3 does not include key exchange algorithms in its cipher suites,
         * but the elliptic curves extension is always required. */
        if (cipher->minimum_required_tls_version >= S2N_TLS13) {
            return 1;
        }

        if (cipher->key_exchange_alg == &s2n_ecdhe || cipher->key_exchange_alg == &s2n_hybrid_ecdhe_kem) {
            return 1;
        }
    }
    return 0;
}

int s2n_pq_kem_is_extension_required(const struct s2n_security_policy *security_policy)
{
    notnull_check(security_policy);
    notnull_check(security_policy->cipher_preferences);
    const struct s2n_cipher_preferences *cipher_preferences = security_policy->cipher_preferences;
    for (int i = 0; i < cipher_preferences->count; i++) {
        struct s2n_cipher_suite *cipher = cipher_preferences->suites[i];
        if (cipher->key_exchange_alg == &s2n_hybrid_ecdhe_kem) {
            return 1;
        }
    }
    return 0;
}

/* Checks whether security policy supports TLS 1.3 based on whether it is configured
 * with TLS 1.3 ciphers. Returns true or false.
 */
bool s2n_security_policy_supports_tls13(const struct s2n_security_policy *security_policy)
{
    notnull_check(security_policy);
    notnull_check(security_policy->cipher_preferences);
    const struct s2n_cipher_preferences *cipher_preferences = security_policy->cipher_preferences;

    for (uint8_t i = 0; i < cipher_preferences->count; i++) {
        if (s2n_is_valid_tls13_cipher(cipher_preferences->suites[i]->iana_value)) {
            return true;
        }
    }

    return false;
}

int s2n_security_policies_init() {
    return 0;
}
