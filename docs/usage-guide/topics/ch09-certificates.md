# Certificates and Authentication

TLS uses certificates to authenticate the server (and optionally the client). The handshake will fail if the client cannot verify the server’s certificate.

Authentication is usually the most expensive part of the handshake. To avoid the cost, consider using [session resumption](./ch11-resumption.md) or [pre-shared keys](./ch13-preshared-keys.md).

## Configuring the Trust Store

To validate the peer’s certificate, a config's local “trust store” must contain a certificate
that can authenticate the peer’s certificate. To add certificates to the trust store, call
`s2n_config_set_verification_ca_location()` or `s2n_config_add_pem_to_trust_store()`.

`s2n_config_new()` initializes the trust store with the default system certificates, which may
include public CAs or other unexpected certificates. If s2n-tls is verifying certificates and does
not require these default system certificates, they should be cleared with
`s2n_config_wipe_trust_store()` before calling `s2n_config_set_verification_ca_location()` or
`s2n_config_add_pem_to_trust_store()`.

Note that the `s2n_verify_host_fn` callback must be implemented to validate the identity of all
received certificates. A client implementation is set by default. If the identity of the received
certificates are implicit (i.e. the certificates are self-signed, or signed by a privately owned
CA), the `s2n_verify_host_fn` callback need not perform any additional validation. However,
`s2n_config_wipe_trust_store()` should be called before adding certificates to the trust store in
this case, in order to avoid implicitly trusting the identity of peers that may present
certificates trusted via an unexpected default system certificate.

Configs created with `s2n_config_new_minimal()` are initialized with empty trust stores. To add
default system certificates to these configs, call `s2n_config_load_system_certs()`.

## Server Authentication

A server must have a certificate and private key pair to prove its identity. s2n-tls supports RSA, RSA-PSS, and ECDSA certificates, and allows one of each type to be added to a config for a given domain name.

Create a new certificate and key pair by calling `s2n_cert_chain_and_key_new()`, then load the pem-encoded data with `s2n_cert_chain_and_key_load_pem_bytes()`.  Call `s2n_config_add_cert_chain_and_key_to_store()` to add the certificate and key pair to the config. When a certificate and key pair is no longer needed, it must be cleaned up with `s2n_cert_chain_and_key_free()`.

A client can add restrictions on the certificate’s hostname by setting a custom `s2n_verify_host_fn` with `s2n_config_set_verify_host_callback()` or `s2n_connection_set_verify_host_callback()`. The default behavior is to require that the hostname match the server name set with `s2n_set_server_name()`.

### SNI

TLS servers will often serve multiple domains from a single IP address, with each domain potentially requiring its own certificate. When a TLS client receives a server's certificate, it will check to ensure that it was issued for the domain that the client is connecting to. As such, the server needs to know which domain the client is connecting to in order to send the correct certificate. This information is communicated to the server via the Server Name Indication (SNI) extension.

#### Client configuration

`s2n_set_server_name()` is used on client connections to specify a domain name in the SNI extension.

#### Server configuration

Each certificate loaded with `s2n_config_add_cert_chain_and_key_to_store()` is automatically associated with every domain name listed in its Subject Alternative Name (SAN) field. The domain names listed in the Common Name (CN) field are used instead if the certificate doesn't contain an SAN field. s2n-tls servers automatically send a certificate that matches the value of the client's SNI extension during the TLS handshake.

s2n-tls servers allow a maximum of 1 certificate to be loaded per domain, per certificate type (RSA, RSA-PSS, ECDSA). By default, a newly loaded certificate with an overlapping domain name will not replace the existing certificate associated with that domain. The `s2n_cert_tiebreak_callback` may be implemented to customize which certificate is selected when an overlapping domain is encountered.

When selecting a certificate to send to the client, s2n-tls servers prefer an exact SNI match before falling back to a certificate with an associated wildcard domain (a domain starting with "*.", covering all subdomains). A default certificate is selected if no SNI match exists, or if the client doesn't send an SNI extension. A default certificate is set when `s2n_config_add_cert_chain_and_key_to_store()` is called for the first time for a given certificate type (RSA, RSA-PSS, ECDSA). `s2n_config_set_cert_chain_and_key_defaults()` may be used to override the default certificates.

## Client / Mutual Authentication

Client authentication is not enabled by default. However, the server can require that the client also provide a certificate, if the server needs to authenticate clients before accepting connections.

Client authentication can be configured by calling `s2n_config_set_client_auth_type()` or `s2n_connection_set_client_auth_type()` for both the client and server. Additionally, the client will need to load a certificate and key pair as described for the server in [Server Authentication](#server-authentication) and the server will need to configure its trust store as described in [Configuring the Trust Store](#configuring-the-trust-store).

When using client authentication, the server MUST implement the `s2n_verify_host_fn`, because the default behavior will likely reject all client certificates.

When using client authentication with TLS1.3, `s2n_negotiate` will report a successful
handshake to clients before the server validates the client certificate. If the server then
rejects the client certificate, the client may later receive an alert while calling `s2n_recv`,
potentially after already having sent application data with `s2n_send`. This is a quirk of the
TLS1.3 protocol message ordering: the server does not send any more handshake messages
after the client sends the client certificate (see the [TLS1.3 state machine](https://www.rfc-editor.org/rfc/rfc8446.html#appendix-A.2)).
There is no security risk, since the client has already authenticated the server,
but it could make handshake failures and authentication errors more difficult to handle.

## Certificate Inspection

Applications may want to know which certificate was used by a server for authentication during a connection, since servers can set multiple certificates. `s2n_connection_get_selected_cert()` will return the local certificate chain object used to authenticate. `s2n_connection_get_peer_cert_chain()` will provide the peer's certificate chain, if they sent one. Use `s2n_cert_chain_get_length()` and `s2n_cert_chain_get_cert()` to parse the certificate chain object and get a single certificate from the chain. Use `s2n_cert_get_der()` to get the DER encoded certificate if desired.

Additionally s2n-tls has functions for parsing certificate extensions on a certificate. Use `s2n_cert_get_x509_extension_value_length()` and `s2n_cert_get_x509_extension_value()` to obtain a specific DER encoded certificate extension from a certificate. `s2n_cert_get_utf8_string_from_extension_data_length()` and `s2n_cert_get_utf8_string_from_extension_data()` can be used to obtain a specific UTF8 string representation of a certificate extension instead. These functions will work for both RFC-defined certificate extensions and custom certificate extensions.

## Certificate Revocation

Certificate revocation is how CAs inform validators that an active certificate should not be trusted. This commonly occurs when a private key has been leaked and the identity of the certificate's owner can no longer be trusted.

s2n-tls supports two methods of certificate revocation: OCSP stapling and CRLs. A fundamental difference between the two is that with OCSP stapling, the peer offering the certificate validates the revocation status of its own certificate. This peer can choose not to send a certificate status response, and applications will have to decide whether or not to fail certificate validation in this case. With CRLs, the application checks the revocation status of the certificate itself, without relying on the peer. However, CRLs must be retrieved and stored by the application, which requires more network and memory utilization than OCSP stapling.

Users who want certificate revocation should look closely at their use-case and decide which method is more appropriate. We suggest using OCSP stapling if you're sure your peer supports OCSP stapling. CRLs should be used if this assumption can't be made. However, s2n-tls does not enable applications to fetch CRLs for received certificates in real-time. This method should only be used if you're able to obtain CRLs in advance for all certificates you expect to encounter.

### OCSP Stapling

Online Certificate Status Protocol (OCSP) is a protocol to establish whether or not a certificate has been revoked. The requester (usually a client), asks the responder (usually a server), to ‘staple’ the certificate status information along with the certificate itself. The certificate status sent back will be either expired, current, or unknown, which the requester can use to determine whether or not to accept the certificate.

OCSP stapling can be applied to both client and server certificates when using TLS1.3, but only to server certificates when using TLS1.2.

To use OCSP stapling, the requester must call `s2n_config_set_status_request_type()` with S2N_STATUS_REQUEST_OCSP. The responder will need to call `s2n_cert_chain_and_key_set_ocsp_data()` to set the raw bytes of the OCSP stapling data.

The OCSP stapling information will be automatically validated if the underlying libcrypto supports OCSP validation. `s2n_config_set_check_stapled_ocsp_response()` can be called with "0" to turn this off. Call `s2n_connection_get_ocsp_response()` to retrieve the received OCSP stapling information for manual verification.

## CRL Validation

> Note: the CRL validation feature in s2n-tls is currently considered unstable, meaning the CRL APIs are subject to change in a future release. To access the CRL APIs, include `s2n/unstable/crl.h`.

Certificate Revocation Lists (CRLs) are lists of issued, unexpired certificates that have been revoked by the CA. CAs publish updated versions of these lists periodically. A validator wishing to verify a certificate obtains a CRL from the CA, validates the CRL, and checks to ensure the certificate is not contained in the list, and therefore has not been revoked by the CA.

The s2n CRL lookup callback must be implemented and set via `s2n_config_set_crl_lookup_cb()` to enable CRL validation in s2n-tls. This callback will be triggered once for each certificate in the certificate chain.

The CRLs for all certificates received in the handshake must be obtained in advance of the CRL lookup callback, outside of s2n-tls. It is not possible in s2n-tls to obtain CRLs in real-time. Applications should load these CRLs into memory, by creating `s2n_crl`s via `s2n_crl_new()`, and adding the obtained CRL data via `s2n_crl_load_pem()`. The `s2n_crl` should be freed via `s2n_crl_free()` when no longer needed.

The application must implement a way to look up the correct CRL for a given certificate. This can be done by comparing the hash of the received certificate's issuer with the hash of the CRL's issuer. The certificate's issuer hash is retrieved via `s2n_crl_lookup_get_cert_issuer_hash()`, and the CRL's issuer hash is retrieved via `s2n_crl_get_issuer_hash()`. Once a CRL is found with a matching issuer hash, call `s2n_crl_lookup_set()` to provide s2n-tls with this CRL.

Call `s2n_crl_lookup_ignore()` to ignore a received certificate if its CRL can't be found. This will cause the certificate validation logic to fail with a `S2N_ERR_CRL_LOOKUP_FAILED` error if the certificate is needed in the chain of trust. The certificate validation logic will not fail if the ignored certificate ends up not being included in the chain of trust.

By default, the CRL validation logic will not fail on CRLs that are not yet active, or are expired. Timestamp validation can optionally be performed in the CRL lookup callback by calling `s2n_crl_validate_active()` and `s2n_crl_validate_not_expired()`.

## Certificate Transparency

Certificate transparency is a framework to store public logs of CA-issued certificates. If requested, certificate owners can send a signed certificate timestamp (SCT) to prove that their certificate exists in these logs. The requester can choose whether or not to accept a certificate based on this information.

Certificate transparency information can be applied to both client and server certificates when using TLS1.3, but only to server certificates when using TLS1.2.

To use certificate transparency, the requester (usually the client) must call `s2n_config_set_ct_support_level()` with S2N_CT_SUPPORT_REQUEST. The responder (usually the server) must call `s2n_cert_chain_and_key_set_sct_list()` to set the raw bytes of the transparency information.

Call `s2n_connection_get_sct_list()` to retrieve the received certificate transparency information. The format of this data is the SignedCertificateTimestampList structure defined in section 3.3 of RFC 6962.
