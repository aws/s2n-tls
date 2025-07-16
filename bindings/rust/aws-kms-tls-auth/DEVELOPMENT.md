# Managing Algorithm & Format Changes.

## Backwards Compatibility: Required
Changes must always be backwards compatible. More specifically, servers must always be able to deserialize earlier versions of PskIdentities, otherwise all of the in-flight communications would fail when an upgrade happens.

## Forward Compatibility: Customer Responsibility
We generally do not promise forwards compatibility: A `0.0.1` V1 enabled server might not be able to handshake with a `0.0.2` V2 enabled client. We will strive to maintain forward compatibility, but if there was ever an upgrade from `AES_256_GCM_SIV` to `AES_512_GCM_SIV`, that would not be forward compatible. 

It would be the customer's responsibility to first deploy version 0.0.2 to all servers, and only then would it be safe to enable `PskVersion::V2`. For further
information see the "Versioning" section in the main module docs.

## Example Version Changes
Below are some examples of scenarios that would require a new version change.
- new field: Adding a new field to either PskIdentity or the inner obfuscated fields would require a version change. 
- new obfuscation algorithm: switch the obfuscation algorithm from AES-256-GCM-SIV to some other AEAD algorithm.
- new HMAC algorithm: If s2n-tls exposed a new HMAC based on SHA512, we would need
a new PskVersion to take advantage of it.

All of these version changes could be accomplished with some variation of the following strategy.

```rust
struct PskIdentity {
    // This is a "rearranged" version of the existing wire format. As long as the
    // PskVersion field is first, we can branch on it when parsing.
    psk_version: PskVersion,
    psk_identity_value: PskIdentityValue
}

enum PskIdentityValue {
    V1(PskIdentityV1),
    V2(PskIdentityV2),
}

impl PskIdentityValue {
    /// version specific logic can be handled in the method
    fn deobfuscate_datakey(&self, obfuscation_key: ObfuscationKey) -> Vec<u8> {
        match self {
            Self::V1(v1_struct) => {
                // e.g. assert on the obfuscation_key version or size
            }
        }
    }
}
```

The above code structure would allow the `DecodeValue` and `EncodeValue` traits to work with both variants. Version specific logic can then be handled in the version-specific structs or the `PskIdentityValue` enum.



