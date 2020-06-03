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
#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"

const struct s2n_security_policy security_policy_20170210 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20170210,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20190801 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20190801,
    .kem_preferences = &kem_preferences_null,
    /* The discrepancy in the date exists because the signature preferences
     * were named when cipher preferences and signature preferences were
     * tracked separately, and we chose to keep the cipher preference
     * name because customers use it.
     */
    .signature_preferences = &s2n_signature_preferences_20200207,
    .ecc_preferences = &s2n_ecc_preferences_20200310,
};

const struct s2n_security_policy security_policy_20190802 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20190801,
    .kem_preferences = &kem_preferences_null,
    /* The discrepancy in the date exists because the signature preferences
     * were named when cipher preferences and signature preferences were
     * tracked separately, and we chose to keep the cipher preference
     * name because customers use it.
     */
    .signature_preferences = &s2n_signature_preferences_20200207,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20170405 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20170405,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_elb_2015_04 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &elb_security_policy_2015_04,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_elb_2016_08 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &elb_security_policy_2015_04,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_elb_tls_1_1_2017_01 = {
    .minimum_protocol_version = S2N_TLS11,
    .cipher_preferences = &elb_security_policy_tls_1_1_2017_01,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_elb_tls_1_2_2017_01 = {
    .minimum_protocol_version = S2N_TLS12,
    .cipher_preferences = &elb_security_policy_tls_1_2_2017_01,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_elb_tls_1_2_ext_2018_06 = {
    .minimum_protocol_version = S2N_TLS12,
    .cipher_preferences = &elb_security_policy_tls_1_2_ext_2018_06,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_elb_fs_2018_06 = {
    .minimum_protocol_version = S2N_TLS12,
    .cipher_preferences = &elb_security_policy_fs_2018_06,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_elb_fs_1_2_2019_08 = {
    .minimum_protocol_version = S2N_TLS12,
    .cipher_preferences = &elb_security_policy_fs_1_2_2019_08,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_elb_fs_1_1_2019_08 = {
    .minimum_protocol_version = S2N_TLS11,
    .cipher_preferences = &elb_security_policy_fs_1_1_2019_08,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_elb_fs_1_2_Res_2019_08 = {
    .minimum_protocol_version = S2N_TLS12,
    .cipher_preferences = &elb_security_policy_fs_1_2_Res_2019_08,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_cloudfront_upstream = {
    .minimum_protocol_version = S2N_SSLv3,
    .cipher_preferences = &cipher_preferences_cloudfront_upstream,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_cloudfront_upstream_tls10 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_cloudfront_upstream_tls10,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_cloudfront_upstream_tls11 = {
    .minimum_protocol_version = S2N_TLS11,
    .cipher_preferences = &cipher_preferences_cloudfront_upstream_tls11,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_cloudfront_upstream_tls12 = {
    .minimum_protocol_version = S2N_TLS12,
    .cipher_preferences = &cipher_preferences_cloudfront_upstream_tls12,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_cloudfront_ssl_v_3 = {
    .minimum_protocol_version = S2N_SSLv3,
    .cipher_preferences = &cipher_preferences_cloudfront_ssl_v_3,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_cloudfront_tls_1_0_2014 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_cloudfront_tls_1_0_2014,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_cloudfront_tls_1_0_2016 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_cloudfront_tls_1_0_2016,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_cloudfront_tls_1_1_2016 = {
    .minimum_protocol_version = S2N_TLS11,
    .cipher_preferences = &cipher_preferences_cloudfront_tls_1_1_2016,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2018 = {
    .minimum_protocol_version = S2N_TLS12,
    .cipher_preferences = &cipher_preferences_cloudfront_tls_1_2_2018,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2019 = {
    .minimum_protocol_version = S2N_TLS12,
    .cipher_preferences = &cipher_preferences_cloudfront_tls_1_2_2019,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_cloudfront_tls_1_2_2020 = {
    .minimum_protocol_version = S2N_TLS12,
    .cipher_preferences = &cipher_preferences_cloudfront_tls_1_2_2020,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_kms_tls_1_0_2018_10 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_kms_tls_1_0_2018_10,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

#if !defined(S2N_NO_PQ)

const struct s2n_security_policy security_policy_kms_pq_tls_1_0_2019_06 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_kms_pq_tls_1_0_2019_06,
    .kem_preferences = &kem_preferences_kms_pq_tls_1_0_2019_06,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_kms_pq_tls_1_0_2020_02 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_kms_pq_tls_1_0_2020_02,
    .kem_preferences = &kem_preferences_kms_pq_tls_1_0_2020_02,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_pq_sike_test_tls_1_0_2019_11 = {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_pq_sike_test_tls_1_0_2019_11,
    .kem_preferences = &kem_preferences_pq_sike_test_tls_1_0_2019_11,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_pq_sike_test_tls_1_0_2020_02 = {
    .minimum_protocol_version = S2N_TLS10,  
    .cipher_preferences = &cipher_preferences_pq_sike_test_tls_1_0_2020_02,
    .kem_preferences = &kem_preferences_pq_sike_test_tls_1_0_2020_02,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

#endif
const struct s2n_security_policy security_policy_kms_fips_tls_1_2_2018_10 = {
    .minimum_protocol_version = S2N_TLS12,
    .cipher_preferences = &cipher_preferences_kms_fips_tls_1_2_2018_10,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20140601 = {
    .minimum_protocol_version = S2N_SSLv3,
    .cipher_preferences = &cipher_preferences_20140601,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20141001 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20141001,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20150202 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20150202,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20150214 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20150214,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20160411 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20160411,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20150306 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20150306,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20160804 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20160804,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20160824 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20160824,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20190122 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20190122,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20190121 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20190121,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20190120 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20190120,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20190214 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20190214,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20170328 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20170328,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_20170718 = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_20170718,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_test_all = {
    .minimum_protocol_version = S2N_SSLv3,
    .cipher_preferences = &cipher_preferences_test_all,
#if !defined(S2N_NO_PQ)
    .kem_preferences = &kem_preferences_kms_pq_tls_1_0_2020_02,
#else
    .kem_preferences = &kem_preferences_null,
#endif
    .signature_preferences = &s2n_signature_preferences_20200207,
    .ecc_preferences = &s2n_ecc_preferences_20200310,
};

const struct s2n_security_policy security_policy_test_all_tls12 = {
    .minimum_protocol_version = S2N_SSLv3,
    .cipher_preferences = &cipher_preferences_test_all_tls12,
#if !defined(S2N_NO_PQ)
    .kem_preferences = &kem_preferences_kms_pq_tls_1_0_2020_02,
#else
    .kem_preferences = &kem_preferences_null,
#endif
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_test_all_fips = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_test_all_fips,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_test_all_ecdsa = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_test_all_ecdsa,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_test_all_rsa_kex = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_test_all_rsa_kex,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,
};

const struct s2n_security_policy security_policy_test_all_tls13 = {
    .minimum_protocol_version = S2N_SSLv3,
    .cipher_preferences = &cipher_preferences_test_all_tls13,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_20200207,
    .ecc_preferences = &s2n_ecc_preferences_20200310,
};

const struct s2n_security_policy security_policy_test_ecdsa_priority = {
    .minimum_protocol_version = S2N_SSLv3,
    .cipher_preferences = &cipher_preferences_test_ecdsa_priority,
    .kem_preferences = &kem_preferences_null,    
    .signature_preferences = &s2n_signature_preferences_20140601,
    .ecc_preferences = &s2n_ecc_preferences_20140601,    
};

const struct s2n_security_policy security_policy_null = {
    .minimum_protocol_version = S2N_TLS10,
    .cipher_preferences = &cipher_preferences_null,
    .kem_preferences = &kem_preferences_null,
    .signature_preferences = &s2n_signature_preferences_null,
    .ecc_preferences = &s2n_ecc_preferences_null,
};

struct s2n_security_policy_selection security_policy_selection[] = {
    { .version="default", .security_policy=&security_policy_20170210, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="default_tls13", .security_policy=&security_policy_20190801, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="default_fips", .security_policy=&security_policy_20170405, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="ELBSecurityPolicy-TLS-1-0-2015-04", .security_policy=&security_policy_elb_2015_04, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    /* Not a mistake. TLS-1-0-2015-05 and 2016-08 are equivalent */
    { .version="ELBSecurityPolicy-TLS-1-0-2015-05", .security_policy=&security_policy_elb_2016_08, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="ELBSecurityPolicy-2016-08", .security_policy=&security_policy_elb_2016_08, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="ELBSecurityPolicy-TLS-1-1-2017-01", .security_policy=&security_policy_elb_tls_1_1_2017_01, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="ELBSecurityPolicy-TLS-1-2-2017-01", .security_policy=&security_policy_elb_tls_1_2_2017_01, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="ELBSecurityPolicy-TLS-1-2-Ext-2018-06", .security_policy=&security_policy_elb_tls_1_2_ext_2018_06, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="ELBSecurityPolicy-FS-2018-06", .security_policy=&security_policy_elb_fs_2018_06, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="ELBSecurityPolicy-FS-1-2-2019-08", .security_policy=&security_policy_elb_fs_1_2_2019_08, .ecc_extension_required=0, .pq_kem_extension_required=0 }, 
    { .version="ELBSecurityPolicy-FS-1-1-2019-08", .security_policy=&security_policy_elb_fs_1_1_2019_08, .ecc_extension_required=0, .pq_kem_extension_required=0 }, 
    { .version="ELBSecurityPolicy-FS-1-2-Res-2019-08", .security_policy=&security_policy_elb_fs_1_2_Res_2019_08, .ecc_extension_required=0, .pq_kem_extension_required=0 }, 
    { .version="CloudFront-Upstream", .security_policy=&security_policy_cloudfront_upstream, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="CloudFront-Upstream-TLS-1-0", .security_policy=&security_policy_cloudfront_upstream_tls10, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="CloudFront-Upstream-TLS-1-1", .security_policy=&security_policy_cloudfront_upstream_tls11, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="CloudFront-Upstream-TLS-1-2", .security_policy=&security_policy_cloudfront_upstream_tls12, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="CloudFront-SSL-v-3", .security_policy=&security_policy_cloudfront_ssl_v_3, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="CloudFront-TLS-1-0-2014", .security_policy=&security_policy_cloudfront_tls_1_0_2014, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="CloudFront-TLS-1-0-2016", .security_policy=&security_policy_cloudfront_tls_1_0_2016, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="CloudFront-TLS-1-1-2016", .security_policy=&security_policy_cloudfront_tls_1_1_2016, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="CloudFront-TLS-1-2-2018", .security_policy=&security_policy_cloudfront_tls_1_2_2018, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="CloudFront-TLS-1-2-2019", .security_policy=&security_policy_cloudfront_tls_1_2_2019, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="CloudFront-TLS-1-2-2020", .security_policy=&security_policy_cloudfront_tls_1_2_2020, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="KMS-TLS-1-0-2018-10", .security_policy=&security_policy_kms_tls_1_0_2018_10, .ecc_extension_required=0, .pq_kem_extension_required=0 },
#if !defined(S2N_NO_PQ)
    { .version="KMS-PQ-TLS-1-0-2019-06", .security_policy=&security_policy_kms_pq_tls_1_0_2019_06, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="KMS-PQ-TLS-1-0-2020-02", .security_policy=&security_policy_kms_pq_tls_1_0_2020_02, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="PQ-SIKE-TEST-TLS-1-0-2019-11", .security_policy=&security_policy_pq_sike_test_tls_1_0_2019_11, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="PQ-SIKE-TEST-TLS-1-0-2020-02", .security_policy=&security_policy_pq_sike_test_tls_1_0_2020_02, .ecc_extension_required=0, .pq_kem_extension_required=0 },
#endif
    { .version="KMS-FIPS-TLS-1-2-2018-10", .security_policy=&security_policy_kms_fips_tls_1_2_2018_10, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20140601", .security_policy=&security_policy_20140601, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20141001", .security_policy=&security_policy_20141001, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20150202", .security_policy=&security_policy_20150202, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20150214", .security_policy=&security_policy_20150214, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20150306", .security_policy=&security_policy_20150306, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20160411", .security_policy=&security_policy_20160411, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20160804", .security_policy=&security_policy_20160804, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20160824", .security_policy=&security_policy_20160824, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20170210", .security_policy=&security_policy_20170210, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20170328", .security_policy=&security_policy_20170328, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20190214", .security_policy=&security_policy_20190214, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20170405", .security_policy=&security_policy_20170405, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20170718", .security_policy=&security_policy_20170718, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20190120", .security_policy=&security_policy_20190120, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20190121", .security_policy=&security_policy_20190121, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20190122", .security_policy=&security_policy_20190122, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20190801", .security_policy=&security_policy_20190801, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20190802", .security_policy=&security_policy_20190802, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="20200207", .security_policy=&security_policy_test_all_tls13, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="test_all", .security_policy=&security_policy_test_all, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="test_all_fips", .security_policy=&security_policy_test_all_fips, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="test_all_ecdsa", .security_policy=&security_policy_test_all_ecdsa, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="test_all_rsa_kex", .security_policy=&security_policy_test_all_rsa_kex, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="test_ecdsa_priority", .security_policy=&security_policy_test_ecdsa_priority, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="test_all_tls12", .security_policy=&security_policy_test_all_tls12, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="test_all_tls13", .security_policy=&security_policy_test_all_tls13, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version="null", .security_policy=&security_policy_null, .ecc_extension_required=0, .pq_kem_extension_required=0 },
    { .version=NULL, .security_policy=NULL, .ecc_extension_required=0, .pq_kem_extension_required=0 }
};

int s2n_find_security_policy_from_version(const char *version, const struct s2n_security_policy **security_policy)
{
    notnull_check(version);
    notnull_check(security_policy);

    for (int i = 0; security_policy_selection[i].version != NULL; i++) {
        if (!strcasecmp(version, security_policy_selection[i].version)) {
            *security_policy = security_policy_selection[i].security_policy;
            return 0;
        }
    }

    S2N_ERROR(S2N_ERR_INVALID_SECURITY_POLICY);
}

int s2n_config_set_cipher_preferences(struct s2n_config *config, const char *version)
{
    GUARD(s2n_find_security_policy_from_version(version, &config->security_policy));
    notnull_check(&config->security_policy->cipher_preferences);
    notnull_check(&config->security_policy->kem_preferences);
    notnull_check(&config->security_policy->signature_preferences);
    notnull_check(&config->security_policy->ecc_preferences);
    return 0;
}

int s2n_connection_set_cipher_preferences(struct s2n_connection *conn, const char *version)
{
    GUARD(s2n_find_security_policy_from_version(version, &conn->security_policy_override));
    notnull_check(&conn->security_policy_override->cipher_preferences);
    notnull_check(&conn->security_policy_override->kem_preferences);
    notnull_check(&conn->security_policy_override->signature_preferences);
    notnull_check(&conn->security_policy_override->ecc_preferences);
    return 0;
}

int s2n_security_policies_init()
{
    for (int i = 0; security_policy_selection[i].version != NULL; i++) {
        const struct s2n_security_policy *security_policy = security_policy_selection[i].security_policy;
        notnull_check(security_policy);
        const struct s2n_cipher_preferences *cipher_preference = security_policy->cipher_preferences;
        notnull_check(cipher_preference);
        const struct s2n_kem_preferences *kem_preference = security_policy->kem_preferences;
        notnull_check(kem_preference);
        const struct s2n_ecc_preferences *ecc_preference = security_policy->ecc_preferences;
        notnull_check(ecc_preference);
        GUARD(s2n_check_ecc_preferences_curves_list(ecc_preference));
        for (int j = 0; j < cipher_preference->count; j++) {
            struct s2n_cipher_suite *cipher = cipher_preference->suites[j];
            notnull_check(cipher);

            /* TLS1.3 does not include key exchange algorithms in its cipher suites,
             * but the elliptic curves extension is always required. */
            if (cipher->minimum_required_tls_version >= S2N_TLS13) {
                security_policy_selection[i].ecc_extension_required = 1;
                security_policy_selection[i].supports_tls13 = 1;
            }

            /* Sanity check that valid tls13 has minimum tls version set correctly */
            S2N_ERROR_IF(s2n_is_valid_tls13_cipher(cipher->iana_value) ^
                (cipher->minimum_required_tls_version >= S2N_TLS13), S2N_ERR_INVALID_SECURITY_POLICY);

            if (s2n_kex_includes(cipher->key_exchange_alg, &s2n_ecdhe)) {
                security_policy_selection[i].ecc_extension_required = 1;
            }

            if (s2n_kex_includes(cipher->key_exchange_alg, &s2n_kem)) {
                security_policy_selection[i].pq_kem_extension_required = 1;
            }
        }

        if (security_policy_selection[i].pq_kem_extension_required == 1) {
            S2N_ERROR_IF(kem_preference->count == 0, S2N_ERR_INVALID_SECURITY_POLICY);
            S2N_ERROR_IF(kem_preference->kems == NULL, S2N_ERR_INVALID_SECURITY_POLICY);
        } else {
            S2N_ERROR_IF(kem_preference->count != 0, S2N_ERR_INVALID_SECURITY_POLICY);
            S2N_ERROR_IF(kem_preference->kems!= NULL, S2N_ERR_INVALID_SECURITY_POLICY);
        }
    }
    return 0;
}

bool s2n_ecc_is_extension_required(const struct s2n_security_policy *security_policy)
{
    if (security_policy == NULL) {
        return false;
    }

    for (int i = 0; security_policy_selection[i].version != NULL; i++) {
        if (security_policy_selection[i].security_policy == security_policy) {
            return 1 == security_policy_selection[i].ecc_extension_required;
        }
    }
    return false;
}

bool s2n_pq_kem_is_extension_required(const struct s2n_security_policy *security_policy)
{
    if (security_policy == NULL) {
        return false;
    }

    for (int i = 0; security_policy_selection[i].version != NULL; i++) {
        if (security_policy_selection[i].security_policy == security_policy) {
            return 1 == security_policy_selection[i].pq_kem_extension_required;
        }
    }
    return false;
}

/* Checks whether cipher preference supports TLS 1.3 based on whether it is configured
 * with TLS 1.3 ciphers. Returns true or false.
 */
bool s2n_security_policy_supports_tls13(const struct s2n_security_policy *security_policy)
{
    if (security_policy == NULL) {
        return false;
    }

    for (uint8_t i = 0; security_policy_selection[i].version != NULL; i++) {
        if (security_policy_selection[i].security_policy == security_policy) {
            return security_policy_selection[i].supports_tls13 == 1;
        }
    }

    /* if cipher preference is not in the official list, compute the result */
    const struct s2n_cipher_preferences *cipher_preferences = security_policy->cipher_preferences;
    if (cipher_preferences == NULL) {
        return false;
    }

    for (uint8_t i = 0; i < cipher_preferences->count; i++) {
        if (s2n_is_valid_tls13_cipher(cipher_preferences->suites[i]->iana_value)) {
            return true;
        }
    }

    return false;
}

int s2n_connection_is_valid_for_cipher_preferences(struct s2n_connection *conn, const char *version)
{
    notnull_check(conn);
    notnull_check(version);
    notnull_check(conn->secure.cipher_suite);

    const struct s2n_security_policy *security_policy = NULL;
    GUARD(s2n_find_security_policy_from_version(version, &security_policy));
    notnull_check(security_policy);

    /* make sure we dont use a tls version lower than that configured by the version */
    if (s2n_connection_get_actual_protocol_version(conn) < security_policy->minimum_protocol_version) {
        return 0;
    }

    struct s2n_cipher_suite *cipher = conn->secure.cipher_suite;
    notnull_check(cipher);
    for (int i = 0; i < security_policy->cipher_preferences->count; ++i) {
        if (0 == memcmp(security_policy->cipher_preferences->suites[i]->iana_value, cipher->iana_value, S2N_TLS_CIPHER_SUITE_LEN)) {
            return 1;
        }
    }

    return 0;
}
