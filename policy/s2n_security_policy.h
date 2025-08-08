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

#include <stdint.h>

#include "tls/s2n_certificate_keys.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_ecc_preferences.h"
#include "tls/s2n_kem_preferences.h"
#include "tls/s2n_security_rules.h"
#include "tls/s2n_signature_scheme.h"

/* The s2n_security_policy struct is used to define acceptable and available
 * algorithms for use in the TLS protocol. Note that the behavior of each field
 * likely differs between different TLS versions, as the mechanics of cipher
 * negotiation often have significant differences between TLS versions.
 *
 * In s2n-tls, the signature_algorithms extension only applies to signatures in
 * CertificateVerify messages. To specify acceptable signature algorithms for
 * certificates the certificate_signature_preferences field should be set in the
 * security policy.
 */
struct s2n_security_policy {
    uint8_t minimum_protocol_version;
    /* TLS 1.0 - 1.2 - cipher preference includes multiple elements such
     * as signature algorithms, record algorithms, and key exchange algorithms
     * TLS 1.3 - cipher preference only determines record encryption
     */
    const struct s2n_cipher_preferences *cipher_preferences;
    /* kem_preferences is only used for Post-Quantum cryptography */
    const struct s2n_kem_preferences *kem_preferences;
    /* This field roughly corresponds to the "signature_algorithms" extension.
     * The client serializes this field of the security_policy to populate the
     * extension, and it is also used by the server to choose an appropriate
     * entry from the options supplied by the client.
     * TLS 1.2 - optional extension to specify signature algorithms other than
     * default: https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.4.1
     * TLS 1.3 - required extension specifying signature algorithms
    */
    const struct s2n_signature_preferences *signature_preferences;
    /* When this field is set, the endpoint will ensure that the signatures on
     * the certificates in the peer's certificate chain are in the specified
     * list. Note that s2n-tls does not support the signature_algorithms_cert
     * extension. Unlike the signature_preferences field, this information is
     * never transmitted to a peer.
    */
    const struct s2n_signature_preferences *certificate_signature_preferences;
    /* This field roughly corresponds to the information in the
     * "supported_groups" extension.
     * TLS 1.0 - 1.2 - "elliptic_curves" extension indicates supported groups
     * for both key exchange and signature algorithms.
     * TLS 1.3 - the "supported_groups" extension indicates the named groups
     * which the client supports for key exchange
     * https://www.rfc-editor.org/rfc/rfc8446#section-4.2.7
     */
    const struct s2n_ecc_preferences *ecc_preferences;
    /* This field determines what public keys are allowed for use. It restricts
     * both the type of the key (Elliptic Curve, RSA w/ Encryption, RSA PSS) and
     * the size of the key. Note that this field structure is likely to change
     * until https://github.com/aws/s2n-tls/issues/4435 is closed.
     */
    const struct s2n_certificate_key_preferences *certificate_key_preferences;
    /* This field controls whether the certificate_signature_preferences apply 
     * to local certs loaded on configs.
     */
    bool certificate_preferences_apply_locally;
    bool rules[S2N_SECURITY_RULES_COUNT];
};

bool s2n_security_policy_supports_tls13(const struct s2n_security_policy *security_policy);

/* Checks to see if a certificate has a signature algorithm that's in our 
 * certificate_signature_preferences list 
 */
S2N_RESULT s2n_security_policy_validate_certificate_chain(const struct s2n_security_policy *security_policy,
        const struct s2n_cert_chain_and_key *cert_key_pair);
S2N_RESULT s2n_security_policy_validate_cert_signature(const struct s2n_security_policy *security_policy,
        const struct s2n_cert_info *info, s2n_error error);
S2N_RESULT s2n_security_policy_validate_cert_key(const struct s2n_security_policy *security_policy,
        const struct s2n_cert_info *info, s2n_error error);
