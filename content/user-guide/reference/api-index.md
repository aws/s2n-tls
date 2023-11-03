+++
title = 'API index'
date = 2023-10-04T17:56:32-07:00
draft = false
weight = 91
+++

> [!NOTE]
> This doc helps the TW organize content. You don't have to keep it forever.
> It could be helpful for people to see shape of the API.
> **bold** entries are not in the user guide.
> *italic* entries mean I don't know if these should be grouped as they are
> I did not check each every entry, particularly in config or connections,
> because it is obvious where those should be discussed.

## Macros

- S2N_API
- S2N_CALLBACK_BLOCKED
- S2N_FAILURE
- S2N_MAXIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION
- S2N_MINIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION
- S2N_SSLv2
- S2N_SSLv3
- S2N_SUCCESS
- S2N_TLS10
- S2N_TLS11
- S2N_TLS12
- S2N_TLS13
- S2N_UNKNOWN_PROTOCOL_VERSION

## s2n_async_pkey

- s2n_async_pkey_fn
- s2n_async_pkey_op_apply()
- s2n_async_pkey_op_free()
- s2n_async_pkey_op_get_input()
- s2n_async_pkey_op_get_input_size()
- s2n_async_pkey_op_get_op_type()
- s2n_async_pkey_op_perform()
- s2n_async_pkey_op_set_output()
- s2n_async_pkey_op_type
- s2n_async_pkey_validation_mode

## s2n_cache

- **s2n_cache_delete_callback**
- **s2n_cache_retrieve_callback**
- **s2n_cache_store_callback**

## s2n_cert_chain_and_key

- s2n_cert_chain_and_key_free()
- s2n_cert_chain_and_key_get_ctx()
- s2n_cert_chain_and_key_get_private_key()
- s2n_cert_chain_and_key_load_pem()
- s2n_cert_chain_and_key_load_pem_bytes()
- s2n_cert_chain_and_key_load_public_pem_bytes()
- s2n_cert_chain_and_key_new()
- s2n_cert_chain_and_key_set_ctx()
- s2n_cert_chain_and_key_set_ocsp_data()
- s2n_cert_chain_and_key_set_sct_list()
- s2n_cert_chain_get_cert()
- s2n_cert_chain_get_length()

## s2n_cert

- s2n_cert_auth_type
- s2n_cert_get_der()
- s2n_cert_get_utf8_string_from_extension_data()
- s2n_cert_get_utf8_string_from_extension_data_length()
- s2n_cert_get_x509_extension_value()
- s2n_cert_get_x509_extension_value_length()
- s2n_cert_private_key
- s2n_cert_public_key
- s2n_cert_tiebreak_callback

## s2n_client_hello

- s2n_client_hello_cb_done()
- s2n_client_hello_cb_mode
- s2n_client_hello_fn
- s2n_client_hello_get_cipher_suites()
- s2n_client_hello_get_cipher_suites_length()
- s2n_client_hello_get_extension_by_id()
- s2n_client_hello_get_extension_length()
- s2n_client_hello_get_extensions()
- s2n_client_hello_get_extensions_length()
- s2n_client_hello_get_raw_message()
- s2n_client_hello_get_raw_message_length()
- s2n_client_hello_get_session_id()
- s2n_client_hello_get_session_id_length()
- s2n_client_hello_get_supported_groups()
- s2n_client_hello_has_extension()

## s2n_config  

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

## s2n_connection

- s2n_connection_add_new_tickets_to_send()
- s2n_connection_append_protocol_preference()
- s2n_connection_append_psk()
- s2n_connection_client_cert_used()
- s2n_connection_free()
- s2n_connection_free_handshake()
- s2n_connection_get_actual_protocol_version()
- s2n_connection_get_alert()
- s2n_connection_get_cipher()
- s2n_connection_get_cipher_iana_value()
- s2n_connection_get_client_auth_type()
- s2n_connection_get_client_cert_chain()
- s2n_connection_get_client_hello()
- s2n_connection_get_client_hello_version()
- s2n_connection_get_client_protocol_version()
- s2n_connection_get_ctx()
- s2n_connection_get_curve()
- s2n_connection_get_delay()
- s2n_connection_get_early_data_status()
- s2n_connection_get_handshake_type_name()
- s2n_connection_get_kem_group_name()
- s2n_connection_get_kem_name()
- s2n_connection_get_last_message_name()
- s2n_connection_get_max_early_data_size()
- s2n_connection_get_negotiated_psk_identity()
- s2n_connection_get_negotiated_psk_identity_length()
- s2n_connection_get_ocsp_response()
- s2n_connection_get_peer_cert_chain()
- s2n_connection_get_read_fd()
- s2n_connection_get_remaining_early_data_size()
- s2n_connection_get_sct_list()
- s2n_connection_get_selected_cert()
- s2n_connection_get_selected_client_cert_digest_algorithm()
- s2n_connection_get_selected_client_cert_signature_algorithm()
- s2n_connection_get_selected_digest_algorithm()
- s2n_connection_get_selected_signature_algorithm()
- s2n_connection_get_server_protocol_version()
- s2n_connection_get_session()
- s2n_connection_get_session_id()
- s2n_connection_get_session_id_length()
- s2n_connection_get_session_length()
- s2n_connection_get_session_ticket_lifetime_hint()
- s2n_connection_get_tickets_sent()
- s2n_connection_get_wire_bytes_in()
- s2n_connection_get_wire_bytes_out()
- s2n_connection_get_write_fd()
- s2n_connection_is_ocsp_stapled()
- s2n_connection_is_session_resumed()
- s2n_connection_is_valid_for_cipher_preferences()
- s2n_connection_new()
- s2n_connection_prefer_low_latency()
- s2n_connection_prefer_throughput()
- s2n_connection_release_buffers()
- s2n_connection_server_name_extension_used()
- s2n_connection_set_blinding()
- s2n_connection_set_cipher_preferences()
- s2n_connection_set_client_auth_type()
- s2n_connection_set_config()
- s2n_connection_set_ctx()
- s2n_connection_set_dynamic_buffers()
- s2n_connection_set_dynamic_record_threshold()
- s2n_connection_set_fd()
- s2n_connection_set_protocol_preferences()
- s2n_connection_set_psk_mode()
- s2n_connection_set_read_fd()
- s2n_connection_set_recv_cb()
- s2n_connection_set_recv_ctx()
- s2n_connection_set_send_cb()
- s2n_connection_set_send_ctx()
- s2n_connection_set_server_early_data_context()
- s2n_connection_set_server_keying_material_lifetime()
- s2n_connection_set_server_max_early_data_size()
- s2n_connection_set_session()
- s2n_connection_set_verify_host_callback()
- s2n_connection_set_write_fd()
- s2n_connection_tls_exporter()
- s2n_connection_use_corked_io()
- s2n_connection_wipe()

## s2n_early_data

- s2n_early_data_cb
- s2n_early_data_status_t
- *s2n_offered_early_data_accept()*
- *s2n_offered_early_data_get_context()*
- *s2n_offered_early_data_get_context_length()*
- *s2n_offered_early_data_reject()*

## s2n_errno

- s2n_errno
- s2n_errno_location()

## s2n_error

- s2n_error_get_type()
- s2n_error_type {...}

### Error type enumerations

- S2N_ERR_T_ALERT
- S2N_ERR_T_BLOCKED
- S2N_ERR_T_CLOSED
- S2N_ERR_T_INTERNAL
- S2N_ERR_T_IO
- S2N_ERR_T_OK
- S2N_ERR_T_PROTO
- S2N_ERR_T_USAGE

## s2n server

- s2n_set_server_name()
- s2n_get_server_name()

## s2n stacktrace

- s2n_get_stacktrace()
- s2n_calculate_stacktrace()
- s2n_free_stacktrace()
- s2n_print_stacktrace()

## s2n_mem

- s2n_mem_set_callbacks()

  - s2n_mem_cleanup_callback
  - s2n_mem_free_callback
  - s2n_mem_init_callback
  - s2n_mem_malloc_callback

### Related to s2n_mem

- s2n_init()
- s2n_cleanup()

## Pre-shared key

- s2n_psk_configure_early_data()
- s2n_psk_free()
- s2n_psk_hmac
- s2n_psk_mode
- s2n_psk_selection_callback
- s2n_psk_set_application_protocol()
- s2n_psk_set_early_data_context()
- s2n_psk_set_hmac()
- s2n_psk_set_identity()
- s2n_psk_set_secret()
- *s2n_offered_psk_free()*
- *s2n_offered_psk_get_identity()*
- *s2n_offered_psk_list_choose_psk()*
- *s2n_offered_psk_list_has_next()*
- *s2n_offered_psk_list_next()*
- *s2n_offered_psk_list_reread()*
- *s2n_offered_psk_new()*
- *s2n_external_psk_new()*

## s2n_rand

- **s2n_rand_cleanup_callback**
- **s2n_rand_init_callback**
- **s2n_rand_mix_callback**
- **s2n_rand_seed_callback**
- **s2n_rand_set_callbacks()**

## s2n_recv

- s2n_recv()
- s2n_recv_early_data()
- s2n_recv_fn

## s2n_send

- s2n_send()
- s2n_send_early_data()
- s2n_send_fn

## s2n_sendv

- s2n_sendv()
- s2n_sendv_with_offset()

## s2n_session_ticket

- s2n_session_ticket_fn
- s2n_session_ticket_get_data()
- s2n_session_ticket_get_data_len()
- s2n_session_ticket_get_lifetime()

## s2n_shutdown

- s2n_shutdown()
- s2n_shutdown_send()

## s2n_stack_traces

- s2n_stack_traces_enabled()
- s2n_stack_traces_enabled_set()

## s2n_strerror

- s2n_strerror()
- s2n_strerror_debug()
- s2n_strerror_name()
- s2n_strerror_source()

## s2n-tls

- **s2n_tls_extension_type {...}**
- **s2n_tls_hash_algorithm {...}**
- **s2n_tls_signature_algorithm {...}**

## Oddly shaped API methods & enums

- s2n_alert_behavior
- s2n_blinding
- s2n_blocked_status
- **s2n_clock_time_nanoseconds**
- s2n_crypto_disable_init()
- **s2n_ct_support_level**
- s2n_disable_atexit()
- **s2n_get_application_protocol()**
- **s2n_get_openssl_version()**
- **s2n_key_log_fn**
- **s2n_max_frag_len**
- **s2n_mode**
- s2n_negotiate()
- s2n_peek()
- **s2n_status_request_type**
- s2n_verify_host_fn
