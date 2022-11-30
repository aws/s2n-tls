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

/**
 * @file crl.h
 *
 * The following APIs enable applications to determine if a received certificate has been revoked by its CA, via
 * Certificate Revocation Lists (CRLs). Please see the CRL Validation section in the usage guide for more information.
 *
 * The CRL APIs are currently considered unstable, since they have been recently added to s2n-tls. After gaining more
 * confidence in the correctness and usability of these APIs, they will be made stable.
 *
 */

struct s2n_crl_lookup;

/**
 * A callback which can be implemented to provide s2n-tls with CRLs to use for CRL validation.
 *
 * This callback is triggered once for each certificate received during the handshake. To provide s2n-tls with a CRL for
 * the certificate, use `s2n_crl_lookup_set()`. To ignore the certificate and not provide a CRL, use
 * `s2n_crl_lookup_ignore()`.
 *
 * This callback can be synchronous or asynchronous. For asynchronous behavior, return success without calling
 * `s2n_crl_lookup_set()` or `s2n_crl_lookup_ignore()`. `s2n_negotiate()` will return S2N_BLOCKED_ON_APPLICATION_INPUT
 * until one of these functions is called for each invoked callback.
 *
 * @param lookup The CRL lookup for the given certificate.
 * @param context Context for the callback function.
 * @returns 0 on success, -1 on failure.
 */
typedef int (*s2n_crl_lookup_callback)(struct s2n_crl_lookup *lookup, void *context);

/**
 * Set a callback to provide CRLs to use for CRL validation.
 *
 * @param config A pointer to the connection config
 * @param s2n_crl_lookup_callback The function to be called for each received certificate.
 * @param context Context to be passed to the callback function.
 * @return S2N_SUCCESS on success, S2N_FAILURE on failure
 */
S2N_API int s2n_config_set_crl_lookup_cb(struct s2n_config *config, s2n_crl_lookup_callback callback, void *context);

/**
 * Allocates a new `s2n_crl` struct.
 *
 * Use `s2n_crl_load_pem()` to load the struct with a CRL pem.
 *
 * The allocated struct must be freed with `s2n_crl_free()`.
 *
 * @return A pointer to the allocated `s2n_crl` struct.
 */
S2N_API struct s2n_crl *s2n_crl_new(void);

/**
 * Loads a CRL with pem data.
 *
 * @param crl The CRL to load with the PEM data.
 * @param pem The PEM data to load `crl` with.
 * @param len The length of the pem data.
 * @return S2N_SUCCESS on success, S2N_FAILURE on error.
 */
S2N_API int s2n_crl_load_pem(struct s2n_crl *crl, uint8_t *pem, size_t len);

/**
 * Frees a CRL.
 *
 * Frees an allocated `s2n_crl` and sets `crl` to NULL.
 *
 * @param crl The CRL to free.
 * @return S2N_SUCCESS on success, S2N_FAILURE on error.
 */
S2N_API int s2n_crl_free(struct s2n_crl **crl);

/**
 * Retrieves the issuer hash of a CRL.
 *
 * This function can be used to find the CRL associated with a certificate received in the s2n_crl_lookup callback. The
 * hash value, `hash`, corresponds with the issuer hash of a certificate, retrieved via
 * `s2n_crl_lookup_get_cert_issuer_hash()`.
 *
 * @param crl The CRL to obtain the hash value of.
 * @param hash A pointer that will be set to the hash value.
 * @return S2N_SUCCESS on success. S2N_FAILURE on failure
 */
S2N_API int s2n_crl_get_issuer_hash(struct s2n_crl *crl, uint64_t *hash);

/**
 * Determines if the CRL is currently active.
 *
 * CRLs contain a thisUpdate field, which specifies the date at which the CRL becomes valid. This function can be called
 * to check thisUpdate relative to the current time. If the thisUpdate date is in the past, the CRL is considered
 * active.
 *
 * @param crl The CRL to validate.
 * @return S2N_SUCCESS if `crl` is active, S2N_FAILURE if `crl` is not active, or the active status cannot be determined.
 */
S2N_API int s2n_crl_validate_active(struct s2n_crl *crl);

/**
 * Determines if the CRL has expired.
 *
 * CRLs contain a nextUpdate field, which specifies the date at which the CRL becomes expired. This function can be
 * called to check nextUpdate relative to the current time. If the nextUpdate date is in the future, the CRL has not
 * expired.
 *
 * If the CRL does not contain a thisUpdate field, the CRL is assumed to never expire.
 *
 * @param crl The CRL to validate.
 * @return S2N_SUCCESS if `crl` has not expired, S2N_FAILURE if `crl` has expired, or the expiration status cannot be determined.
 */
S2N_API int s2n_crl_validate_not_expired(struct s2n_crl *crl);

/**
 * Retrieves the issuer hash of the certificate.
 *
 * The CRL lookup callback is triggered once for each received certificate. This function is used to get the issuer hash
 * of this certificate. The hash value, `hash`, corresponds with the issuer hash of the CRL, retrieved via
 * `s2n_crl_get_issuer_hash()`.
 *
 * @param lookup The CRL lookup for the given certificate.
 * @param hash A pointer that will be set to the hash value.
 * @return S2N_SUCCESS on success, S2N_FAILURE on failure.
 */
S2N_API int s2n_crl_lookup_get_cert_issuer_hash(struct s2n_crl_lookup *lookup, uint64_t *hash);

/**
 * Provide s2n-tls with a CRL from the CRL lookup callback.
 *
 * A return function for `s2n_crl_lookup_cb`. This function should be used from within the CRL lookup callback to
 * provide s2n-tls with a CRL for the given certificate. The provided CRL will be included in the list of CRLs to use
 * when validating the certificate chain.
 *
 * To skip providing a CRL from the callback, use `s2n_crl_lookup_ignore()`.
 *
 * @param lookup The CRL lookup for the given certificate.
 * @param crl The CRL to include in the list of CRLs used to validate the certificate chain.
 * @return S2N_SUCCESS on success, S2N_FAILURE on failure.
 */
S2N_API int s2n_crl_lookup_set(struct s2n_crl_lookup *lookup, struct s2n_crl *crl);

/**
 * Skip providing a CRL from the CRL lookup callback.
 *
 * A return function for `s2n_crl_lookup_cb`. This function should be used from within the CRL lookup callback to ignore
 * the certificate, and skip providing s2n-tls with a CRL.
 *
 * If a certificate is ignored, and is ultimately included in the chain of trust, certificate chain validation will
 * fail with a S2N_ERR_CRL_LOOKUP_FAILED error. However, if the certificate is extraneous and not included in the chain
 * of trust, validation is able to proceed.
 *
 * @param lookup The CRL lookup for the given certificate.
 * @return S2N_SUCCESS on success, S2N_FAILURE on failure.
 */
S2N_API int s2n_crl_lookup_ignore(struct s2n_crl_lookup *lookup);
