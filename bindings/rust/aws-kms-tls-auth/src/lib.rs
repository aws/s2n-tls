#![allow(dead_code)]
// allow dead code for piece-wise commits

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The KMS TLS PSK Provider provides a way to get a mutually authenticated TLS
//! connection using IAM credentials, KMS, and the external PSK feature of TLS 1.3.
//!
//! The client must have IAM credentials that allow `generate-datakey` API calls
//! for some KMS Key.
//!
//! The server must have IAM credentials that allow `decrypt` calls.
//!
//! ## Generate Data Key
//! The client first calls generate data key. The plaintext datakey is used as the
//! PSK secret, and is the input for [`s2n_tls::psk::Builder::set_secret`]. The
//! ciphertext datakey is set as the PSK identity (sort of, see PSK Identity section).
//!
//! ## Decrypt
//! The client then connects to the server, sending the PSK as part of its client
//! hello. The server then retrieves the PSK identity (ciphertext datakey) from the
//! client hello and calls the KMS decrypt API to retrieve the plaintext datakey.
//!
//! At this point it can construct the same PSK that the client used, so the handshake
//! is able to continue and complete successfully.
//!
//! ## Caching
//! The server component [`PskReceiver`] will cache successfully decrypted ciphertexts.
//! This means that the first handshake from a new client will result in a network
//! call to KMS, but future handshakes from that client will be able to retrieve
//! the plaintext datakey from memory.
//!
//! Note that this cache is bounded to a size of [`MAXIMUM_KEY_CACHE_SIZE`].
//!
//! ## Rotation
//! The client component [`PskProvider`] will automatically rotate the PSK. This
//! is controlled by the [`KEY_ROTATION_PERIOD`] which is currently 24 hours.
//!
//! ## PSK Identity
//! The ciphertext datakey is not directly used as the PSK identity. Because PSK
//! identities can be observed on the wire, the ciphertext is first encrypted using
//! the obfuscation key. This prevents any possible data leakage of ciphertext details.
//!
//! ## Deployment Concerns
//! The obfuscation key that the [`PskProvider`] is configured with must also
//! be supplied to the [`PskReceiver`]. Otherwise handshakes will fail.
//!
//! The KMS Key ARN that the [`PskProvider`] is configured with must be supplied
//! to the [`PskReceiver`]. Otherwise handshakes will fail.
//!
//! Note that the [`PskReceiver`] supports lists for both of these items, so
//! zero-downtime migrations are possible. _Example_: if the client fleet wanted
//! to switch from Key A to Key B it would go through the following stages
//! 1. client -> [A], server -> [A]
//! 2. client -> [A], server -> [A, B]
//! 3. client -> [A, B], server -> [A, B]
//! 4. client ->    [B], server -> [A, B]
//! 5. client ->    [B], server ->    [B]
//!
//! ## Versioning
//!
//! [`PskVersion`] changes are backwards compatible, but not necessarily forwards
//! compatible.
//!
//! > Note that crate versions and formats below are an example only. There are no
//! > PskVersion changes currently planned. When a new PskVersion is made available
//! > it will be communicated by marking the old PskVersion as `#[deprecated]`.
//!
//! Example:
//! - `PskVersion::V1`: available in `0.0.1`
//! - `PskVersion::V2`: available in `0.0.2`
//!
//! A [`PskReceiver`] will support all available `PskVersion`s, and does not have
//! an explicitly configured version. The `PskReceiver` from `0.0.2` will be able
//! to handshake with V1 and V2 configured clients. The `PskReceiver` from `0.0.1`
//! will only be able to handshake V1 configured clients.
//!
//! A [`PskProvider`] has an explicitly configured `PskVersion`. The `PskProvider`
//! from `0.0.2` can be configured to send `PskVersion::V1` xor `PskVersion::V2`.
//! The `PskProvider` from `0.0.1` can only be configured with `PskVersion::V1`.
//!
//! Consider a fleet of clients and server that is currently using `PskVersion::V1`
//! with crate version `0.0.1`. Upgrading to `PskVersion::V2` would require the
//! following steps:
//!
//! 1. Deploy `0.0.2` across all clients and server. This will allow all `PskReceiver`s
//!    to understand both `PskVersion::V1` and `PskVersion::V2`.
//! 2. Enable `PskVersion::V2` on the `PskProvider` through the `psk_version`
//!    argument in [`PskProvider::initialize`]. Because all of servers understand
//!    both V1 and V2 formats this can be deployed without any downtime.
//!
//! Note that these steps MUST NOT overlap. A `0.0.1` `PskReceiver` will fail to
//! handshake with a `PskProvider` configured to send `PskVersion::V2`.

mod codec;
mod identity;
mod prefixed_list;
mod provider;
mod psk_parser;
mod receiver;
#[cfg(test)]
pub(crate) mod test_utils;

use s2n_tls::error::Error as S2NError;
use std::time::Duration;

pub type KeyArn = String;
pub use identity::{ObfuscationKey, PskVersion};
pub use provider::PskProvider;
pub use receiver::PskReceiver;

// We have "pub" use statement so these can be fuzz tested
pub use codec::DecodeValue;
pub use psk_parser::PresharedKeyClientHello;

const MAXIMUM_KEY_CACHE_SIZE: usize = 100_000;
const PSK_SIZE: usize = 32;
const AES_256_GCM_SIV_KEY_LEN: usize = 32;
const AES_256_GCM_SIV_NONCE_LEN: usize = 12;
/// The key is automatically rotated every period. Currently 24 hours.
const KEY_ROTATION_PERIOD: Duration = Duration::from_secs(3_600 * 24);
/// The maximum allowed age of a PSK identity.
///
/// PSK identities include their creation time. The server will reject the PSK
/// identity and fail the handshake if the PSK identity is older than this value.
const PSK_IDENTITY_VALIDITY: Duration = Duration::from_secs(60);

fn psk_from_material(identity: &[u8], secret: &[u8]) -> Result<s2n_tls::psk::Psk, S2NError> {
    let mut psk = s2n_tls::psk::Psk::builder()?;
    psk.set_hmac(s2n_tls::enums::PskHmac::SHA384)?;
    psk.set_identity(identity)?;
    psk.set_secret(secret)?;
    psk.build()
}

#[cfg(test)]
mod tests {
    use crate::{AES_256_GCM_SIV_KEY_LEN, AES_256_GCM_SIV_NONCE_LEN};
    use aws_lc_rs::aead::AES_256_GCM_SIV;

    /// `key_len()` and `nonce_len()` aren't const functions, so we define
    /// our own constants to let us use those values in things like array sizes.
    #[test]
    fn constant_check() {
        assert_eq!(AES_256_GCM_SIV_KEY_LEN, AES_256_GCM_SIV.key_len());
        assert_eq!(AES_256_GCM_SIV_NONCE_LEN, AES_256_GCM_SIV.nonce_len());
    }
}
