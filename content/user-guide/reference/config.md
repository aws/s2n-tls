+++
title = 'Configuration'
date = 2023-10-04T17:55:31-07:00
draft = false
weight = 60
+++

- s2n_config_accept_max_fragment_length()
- s2n_config_add_cert_chain_and_key()
- s2n_config_add_cert_chain_and_key_to_store()
- s2n_config_add_dhparams()
- s2n_config_add_pem_to_trust_store()
- s2n_config_add_ticket_crypto_key()
- s2n_config_append_protocol_preference()
- s2n_config_disable_x509_time_verification()
- s2n_config_disable_x509_verification()
- s2n_config_enable_cert_req_dss_legacy_compat()
- s2n_config_free()
- s2n_config_free_cert_chain_and_key()
- s2n_config_free_dhparams()
- s2n_config_get_client_auth_type()
- s2n_config_get_ctx()
- s2n_config_load_system_certs()
- s2n_config_new()
- s2n_config_new_minimal()
- s2n_config_send_max_fragment_length()
- s2n_config_set_alert_behavior()
- s2n_config_set_async_pkey_callback()
- s2n_config_set_async_pkey_validation_mode()
- s2n_config_set_cache_delete_callback()
- s2n_config_set_cache_retrieve_callback()
- s2n_config_set_cache_store_callback()
- s2n_config_set_cert_chain_and_key_defaults()
- s2n_config_set_cert_tiebreak_callback()
- s2n_config_set_check_stapled_ocsp_response()
- s2n_config_set_cipher_preferences()
- s2n_config_set_client_auth_type()
- s2n_config_set_client_hello_cb()
- s2n_config_set_client_hello_cb_mode()
- s2n_config_set_ct_support_level()
- s2n_config_set_ctx()
- s2n_config_set_early_data_cb()
- s2n_config_set_extension_data()
- s2n_config_set_initial_ticket_count()
- s2n_config_set_key_log_cb()
- s2n_config_set_max_cert_chain_depth()
- s2n_config_set_monotonic_clock()
- s2n_config_set_protocol_preferences()
- s2n_config_set_psk_mode()
- s2n_config_set_psk_selection_callback()
- s2n_config_set_recv_multi_record()
- s2n_config_set_send_buffer_size()
- s2n_config_set_server_max_early_data_size()
- s2n_config_set_session_cache_onoff()
- s2n_config_set_session_state_lifetime()
- s2n_config_set_session_ticket_cb()
- s2n_config_set_session_tickets_onoff()
- s2n_config_set_status_request_type()
- s2n_config_set_ticket_decrypt_key_lifetime()
- s2n_config_set_ticket_encrypt_decrypt_key_lifetime()
- s2n_config_set_verification_ca_location()
- s2n_config_set_verify_after_sign()
- s2n_config_set_verify_host_callback()
- s2n_config_set_wall_clock()
- s2n_config_wipe_trust_store()

`s2n_config` objects are used to change the default settings of a s2n-tls connection. Use `s2n_config_new()` to create a new config object. To associate a config with a connection call `s2n_connection_set_config()`. A config should not be altered once it is associated with a connection as this will produce undefined behavior. It is not necessary to create a config object per connection; one config object should be used for many connections. Call `s2n_config_free()` to free the object when no longer needed. _Only_ free the config object when all connections using it have been freed.

Calling `s2n_config_new()` can have a performance cost during config creation due to loading default system certificates into the trust store (see [Configuring the Trust Store](#configuring-the-trust-store)). For increased performance, use `s2n_config_new_minimal()` when system certificates are not needed for certificate validation.

Most commonly, a `s2n_config` object is used to set the certificate key pair for authentication and change the default security policy. See the sections for [certificates](#certificates-and-authentication) and [security policies](#security-policies) for more information on those settings.

## Overriding the configuration

Some `s2n_config` settings can be overridden on a specific connection if desired. For example, `s2n_config_append_protocol_preference()` appends a list of ALPN protocols to a `s2n_config`. Calling the `s2n_connection_append_protocol_preference()` API will override the list of ALPN protocols for an individual connection. Not all config APIs have a corresponding connection API so if there is one missing contact us with an explanation on why it is required for your use-case.
