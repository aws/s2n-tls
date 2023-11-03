+++
title = 'Certificates and keys'
date = 2023-10-04T17:56:32-07:00
draft = false
weight = 30
+++

## What's in **Certificates and keys**

### s2n_async_pkey

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

### s2n_cert_chain_and_key

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

### s2n_cert

- s2n_cert_auth_type
- s2n_cert_get_der()
- s2n_cert_get_utf8_string_from_extension_data()
- s2n_cert_get_utf8_string_from_extension_data_length()
- s2n_cert_get_x509_extension_value()
- s2n_cert_get_x509_extension_value_length()
- s2n_cert_private_key
- s2n_cert_public_key
- s2n_cert_tiebreak_callback

### Pre-shared key

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

### Certificates

### Private key operation related calls

### TLS 1.3 pre-shared keys
