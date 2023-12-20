# Pre-shared Keys

s2n-tls supports pre-shared keys (PSKs) as of TLS1.3. PSKs allow users to establish secrets outside of the handshake, skipping certificate exchange and authentication.

## Benefits of Using Pre-Shared Keys

Using pre-shared keys can avoid the need for public key operations. This is useful in performance-constrained environments with limited CPU power. PSKs may also be more convenient from a key management point of view: If the system already has a mechanism for sharing secrets, that mechanism can be reused for TLS PSKs.

## Security Considerations

A PSK must not be shared between more than one server and one client. An entity that acts as both a server and a client should not use the same PSK for both roles. For more information see: [Selfie: reflections on TLS 1.3 with PSK.](https://eprint.iacr.org/2019/347.pdf)


## Configuring External Pre-Shared Keys

Both clients and servers will need to create and append a PSK to a connection in order to negotiate that PSK. Call `s2n_external_psk_new()` to allocate memory for a PSK object. Call `s2n_psk_set_identity()` to set a unique identifier for the PSK. Note that this identity will be transmitted over the network unencrypted, so do not include any confidential information in it. Call `s2n_psk_set_secret()` to set the secret value for a given PSK. Deriving a shared secret from a password or other low-entropy source is _not_ secure and is subject to dictionary attacks. See [this RFC](https://www.rfc-editor.org/rfc/rfc9257.html#name-recommendations-for-externa) for more guidelines on creating a secure PSK secret. Call `s2n_psk_set_hmac()` to change the hmac algorithm (defaults to **S2N_PSK_HMAC_SHA256**) for a given PSK. Note that the hmac algorithm may influence server cipher-suite selection.

Call `s2n_connection_append_psk()` to append the newly created PSK to the connection. Both the server and client should call this API to add PSKs to their connection. PSKs that are appended first will be preferred over PSKs appended last unless custom PSK selection logic is implemented. Use `s2n_psk_free()` to free the memory allocated for a PSK once you have associated it with a connection.

External PSKs and Session Resumption cannot both be used in TLS13. Therefore, users must pick which mode they are using by calling `s2n_config_set_psk_mode()` prior to the handshake. Additionally, `s2n_connection_set_psk_mode()` overrides the PSK mode set on the config for a particular connection.

## Selecting a Pre-Shared Key

By default, a server chooses the first identity in its PSK list that also appears in the client's PSK list. The `s2n_psk_selection_callback` is available if you would like to implement your own PSK selection logic. Currently, this callback is not asynchronous. Call `s2n_config_set_psk_selection_callback()` to associate your `s2n_psk_selection_callback` with a config.

The `s2n_psk_selection_callback` will provide the list of PSK identities sent by the client in the **psk_list** input parameter. You will need to create an offered PSK object by calling `s2n_offered_psk_new()` and pass this object as a parameter in `s2n_offered_psk_list_next()` in order to populate the offered PSK object. Call `s2n_offered_psk_list_has_next()` prior to calling `s2n_offered_psk_list_next()` to determine if there exists another PSK in the **psk_list**. Call `s2n_offered_psk_get_identity()` to get the identity of a particular **s2n_offered_psk**.

Call `s2n_offered_psk_list_choose_psk()` to choose a particular **s2n_offered_psk** to be used for the connection. Note that the server must have already configured the corresponding PSK on the connection using `s2n_connection_append_psk()`. To disable PSKs for the connection and perform a full handshake instead, set the PSK identity to NULL. Call `s2n_offered_psk_free()` once you have chosen a particular PSK to free the memory allocated.

If desired, `s2n_offered_psk_list_reread()` returns the offered PSK list to its original read state. After `s2n_offered_psk_list_reread()` is called, the next call to `s2n_offered_psk_list_next()` will return the first PSK in the offered PSK list.

Use `s2n_connection_get_negotiated_psk_identity()` to retrieve the PSK identity selected by the server for the connection.

In the following example, `s2n_psk_selection_callback` chooses the first client offered PSK identity present in an external store.

```c
int s2n_psk_selection_callback(struct s2n_connection *conn, void *context,
                               struct s2n_offered_psk_list *psk_list)
{
    struct s2n_offered_psk *offered_psk = s2n_offered_psk_new();

    while (s2n_offered_psk_list_has_next(psk_list)) {
        uint8_t *client_psk_id = NULL;
        uint16_t client_psk_id_len = 0;

        s2n_offered_psk_list_next(psk_list, offered_psk);
        s2n_offered_psk_get_identity(offered_psk, &client_psk_id, &client_psk_id_len);
        struct s2n_psk *psk = user_lookup_identity_db(client_psk_id, client_psk_id_len);

        if (psk) {
            s2n_connection_append_psk(conn, psk);
            s2n_offered_psk_list_choose_psk(psk_list, offered_psk);
            break;
        }
    }
    s2n_offered_psk_free(&offered_psk);
    return S2N_SUCCESS;
}
```
