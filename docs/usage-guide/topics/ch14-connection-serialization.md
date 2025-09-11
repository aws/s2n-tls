# Connection Serialization

Connection Serialization allows TLS connection state to be serialized into a byte string. This allows the connection to be transported to a different box or stored to disk.

<div class="warning">
This feature is dangerous. It provides cryptographic material from a TLS session in plaintext. An attacker with access to the serialized connection can decrypt any past and future communications from the connection. Users MUST both encrypt and MAC the contents of the serialized connection to provide secrecy and integrity if the serialized connection is transported off-box. 

The simplest way to provide secrecy and integrity is to transport the serialized connection using a protocol like TLS which protects the secrecy and integrity of all transported data.
</div>

## Use Case
Connection Serialization is a feature used to support advanced, exceptional use cases. Most customers will not find it useful.

One use case for connection serialization is to enable a more complete TLS offload. Traditional private-key offloading allows the the certificate private key to be stored separately from the application server, but connection-serialization TLS offloading allows all TLS materials and TLS configuration to be stored separately from the application server.

### Private Key Offloading
For reference, this is a common private key offloading architecture:
```
 client           application server                  key store     
               ┌─────────────────────────┐                       
┌─────┐        │     s2n-tls config      ┼───────►┌─────────────┐
│     ┼───────►│                         │◄───────┼ private key │
└─────┘        │ public key (x509 chain) │    ▲   └─────────────┘
               └─────────────────────────┘    │                  
                                              │                  
                                  server sends material to sign  
                                  key store returns signature    
```

The client will send TLS handshake bytes (e.g. the Client Hello message) to the application server. The server sends all private key operations to the key store, but the public x509 certificate chain and TLS configuration are still owned by the application server.

### Connection-Serialization TLS Offloading
```
                                        key store           
 client    application server   ┌──────────────────────────┐
                                │     s2n-tls config       │
┌─────┐        ┌─────┐ ────────►│                          │
│     ┼───────►│     │◄─────────┼       private key        │
└─────┘        └─────┘     ▲    │                          │
                           │    │  public key (x509 chain) │
                           │    └──────────────────────────┘
                           │                                
                     server sends handshake bytes           
                     key store returns serialized connection
```
In connection-serialization TLS Offloading, the application server will forward all of the handshake bytes to the key store. For the duration of the handshake, the application server is behaving as an L4 proxy, and doesn't parse any of the TLS protocol. Once the TLS handshake is complete, the key store will call `s2n_connection_serialize()` to serialize the connection to bytes, and send it back to the application server. The application server will then deserialize the connection using `s2n_connection_deserialize()`. At this point, the application server can read and write application data to the client.

In this architecture the application server does not store any TLS certificate material, and it does not own the TLS configuration.

## Usage

To enable connection serialization, applications must first set a serialization version on the config using `s2n_config_set_serialization_version()`. Setting a version prevents forwards-incompatible changes from causing deserialization failures. See [Serialization Version Deployment](ch13-serialization.md#serialization-version-upgrade) for more information.

To serialize a connection, applications must first obtain a large enough buffer to store the serialized connection. The size of the serialized connection can be obtained with `s2n_connection_serialization_length()`. The serialized connection can then be written into the buffer with `s2n_connection_serialize()`.

To deserialize the connection, call `s2n_connection_deserialize()`. Note that a serialized connection stores a minimal amount of state. So while the deserialized connection can be used to read and write application data, most connection level configuration will not be preserved, and connection getters may not function normally.

## Serialization Version Upgrade
When upgrading serialization versions, care must be taken to prevent serialization failures. Connection Serialization is not forwards compatible. This means that old versions of s2n-tls will not be able to deserialize connections using new serialization versions.

Consider the case where s2n-tls version `1.6.0` supports serialization version `V1`, and s2n-tls version `1.6.1` supports serialization versions `V1` and `V2`. To use serialization version `V2`, all application instances must first be updated to `1.6.1`, and only then is it safe to enable serialization version `V2`. Connection serialization is backwards compatible, so it is safe for s2n-tls version `1.6.1` to be deserializing both `V1` and `V2` connections.

If `V2` connection serialization is enabled while some application instances are still running s2n-tls `1.6.0`, then `1.6.0` application instances will fail to deserialize `V2` connections.
