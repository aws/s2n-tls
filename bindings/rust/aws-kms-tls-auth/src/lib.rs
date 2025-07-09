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
//! The server component [`KmsPskReceiver`] will cache successfully decrypted ciphertexts.
//! This means that the first handshake from a new client will result in a network
//! call to KMS, but future handshakes from that client will be able to retrieve
//! the plaintext datakey from memory.
//!
//! Note that this cache is bounded to a size of [`MAXIMUM_KEY_CACHE_SIZE`].
//!
//! ## Rotation
//! The client component [`KmsPskProvider`] will automatically rotate the PSK. This
//! is controlled by the [`KEY_ROTATION_PERIOD`] which is currently 24 hours.
//!
//! ## PSK Identity
//! The ciphertext datakey is not directly used as the PSK identity. KMS ciphertexts
//! have observable regularities, so we first obfuscate the ciphertext using the
//! provided obfuscation key.
//!
//! ## Deployment Concerns
//! The obfuscation key that the [`KmsPskProvider`] is configured with must also
//! be supplied to the [`KmsPskReceiver`]. Otherwise handshakes will fail.
//!
//! The KMS Key ARN that the [`KmsPskProvider`] is configured with must be supplied
//! to the [`KmsPskReceiver`]. Otherwise handshakes will fail.
//!
//! Note that the [`KmsPskReceiver`] supports lists for both of these items, so
//! zero-downtime migrations are possible. _Example_: if the client fleet wanted
//! to switch from Key A to Key B it would go through the following stages
//! 1. client -> [A], server -> [A]
//! 2. client -> [A], server -> [A, B]
//! 3. client -> [A, B], server -> [A, B]
//! 4. client ->    [B], server -> [A, B]
//! 5. client ->    [B], server ->    [B]

mod client_hello_parser;
mod codec;
mod prefixed_list;
