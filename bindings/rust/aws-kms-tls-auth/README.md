# aws-kms-tls-auth

This crate provides a way to perform TLS authentication using the AWS Key Management Service (KMS) and Identity and Access Management (IAM). The only supported TLS implementation is currently [s2n-tls](https://github.com/aws/s2n-tls), but if you are interested in support for other TLS implementations please open a [github issue](https://github.com/aws/s2n-tls/issues/new/choose).

Clients use the [generateMAC](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html) API to create a secret shared across the fleet. Clients then derive a unique secret for each connection, which the server is able to retrieve based on the PSKIdentity. The TLS connection then proceeds using the TLS 1.3 out-of-band PSK mechanism. Other TLS protocols are not supported. 

The authenticated property is "the peer has kms:GenerateMac permissions on the KMS HMAC Key".

Note that this library is a data-plane dependency on KMS. If KMS is down for more than 24 hours, handshakes will fail.

# infrastructure setup
- KMS HMAC Key: Library users must provision a [KMS HMAC key](https://docs.aws.amazon.com/kms/latest/developerguide/hmac.html) using an [HMAC_384](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html#hmac-key-specs) key spec.
- IAM Role: clients and servers must be configured with an IAM role that has `kms:GenerateMac` permissions on the created HMAC key.
- Rotation Failure Notification: Applications must supply a "failure notification" closure to the `PskProvider` and `PskReceiver`. This closure is invoked whenever there is a failure to rotate the epoch secret. Customers should alarm on this value. If a rotation fails, rotation will be reattempted in 1 hour. If rotation fails for 24 hours, handshakes will then fail.

# High Level Design

There are three components to this design

* epoch_secret: This is derived from the KMS HMAC key, and is shared across the fleet. Rotated daily
* PSK Secret: This is derived from the epoch_secret and a unique nonce. This is unique per-connection
* PSK Identity: This is a plaintext identifier that is sent from the client to the server. unique per-connection.

### Daily Secret

The daily secret is generated using the KMS [GenerateMac](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html) API. The message that the MAC is derived over will be an 8 bytes string of the days elapsed since the unix epoch. The HMAC algorithm will be selected to match the HMAC algorithm used in the underlying TLS protocol. This is not customer configurable, and will use `HMAC_SHA_384`.

```rust
const KEY_PURPOSE: &[u8]: "aws-kms-tls-auth-daily-secret"

let key_epoch: u64 = seconds_since_unix_epoch() / (3_600 * 24)
let message = concat(key_epoch, KEY_PURPOSE)

let epoch_secret: Vec<u8> = kms.generate_mac(
    key_id: KEY_ID,
    mac_algorithm: HMAC_SHA_384
    message: message,
)
```

### PSK Secret

First, the client will generate a random session_name to be used as a nonce. `session_name` will be 32 bytes long. This will be used along with `epoch_secret` in HKDF to derive the connection-specific secret. The digest used will match that used in the KMS HMAC and the underlying TLS protocol - SHA384.

```rust
let session_name: [u8; 32] = random_bytes();
let psk_secret = HKDF(
    secret: epoch_secret,
    info: session_name,
    salt: null,
)
```

### PSK Identity

The PSK identity is sent in plaintext in the client hello.

Note that we support a server trusting multiple KMS HMAC keys. This is necessary to allow for customers to manually rotate KMS keys in response to extraordinary circumstances without availability impact.

If a server trusts both `keyA` and `keyB`, then the client will need to communicate which key it used to derive its PSK. The naive solution would be to just include `keyA` or `keyB` in plaintext in the PSK Identity. However, this would leak information about “fleet membership”, because it is sent in the clear. Ideally, the PSK identity would not leak this information.

To do this we calculate a `kms_key_binder` which incorporates the 

* kms key arn: the key that was used to generate the daily secret
* session_name: this makes the kms key binder unique per connection, preventing information from being correlated across multiple connections from a single client.
* epoch_secret: without secret information, then an attacker would be able to calculate whether the kms_key_binder is valid for some specific key, because the `session_name` is public information.

```rust
KMS_KEY_ARN: Vec<u8> = "arn:123456789:iw78his7w3hg4if7g";

let kms_key_binder: Vec<u8> = HKDF(
    secret: epoch_secret,
    info: KMS_KEY_ARN,
    salt: session_name
)

let psk_identity = concat(key_epoch, session_name, kms_key_binder)
```

### Server Flow

Upon a receiving a PSK identity, the server will parse out `key_epoch`, `session_name`, and the `kms_key_binder`.

Then for each KMS HMAC Key that it trusts, it would repeat the PSK secret and PSK identity derivation process. If one of the derived PSK identities matches the client’s PSK identity, then that will be the PSK used in the connection. If no PSK identities match, then the connection is rejected and the handshake will fail.

### Material Disclosure Impact

If an attacker obtains an epoch secret, then they will be able to impersonate a server or a client. They can not decrypt any conversations between other peers, because TLS 1.3 PSK authentication performs an additional DHE key exchange.

If an attacker obtains a connection specific secret, then they will be able impersonate a client to any server. They will not be able to impersonate a server, or decrypt any client communications.