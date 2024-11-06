# Configuring the Connection

`s2n_config` objects are used to change the default settings of a s2n-tls connection, such as loading the certificate, configuring session resumption, etc. Use `s2n_config_new()` to create a new config object. To associate a config with a connection call `s2n_connection_set_config()`. Users should complete all configuration before associating config with a connection. Mutating the config after association will produce undefined behavior. It is not necessary to create a config object per connection; one config object should be used for many connections. Call `s2n_config_free()` to free the object when no longer needed. _Only_ free the config object when all connections using it have been freed.

Calling `s2n_config_new()` can have a performance cost during config creation due to loading
default system certificates into the trust store (see [Configuring the Trust Store](./ch09-certificates.md#configuring-the-trust-store)).
For increased performance, use `s2n_config_new_minimal()` when system certificates are not needed
for certificate validation.

Most commonly, a `s2n_config` object is used to set the certificate key pair for authentication and change the default security policy. See the sections for [certificates](./ch09-certificates.md) and [security policies](./ch06-security-policies.md) for more information on those settings.

## Overriding the Config

Some `s2n_config` settings can be overridden on a specific connection if desired. For example, `s2n_config_append_protocol_preference()` appends a list of ALPN protocols to a `s2n_config`. Calling the `s2n_connection_append_protocol_preference()` API will override the list of ALPN protocols for an individual connection. Not all config APIs have a corresponding connection API so if there is one missing contact us with an explanation on why it is required for your use-case.
