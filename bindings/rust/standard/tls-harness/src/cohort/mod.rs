// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module contains `TlsConnection` impls for various implementations of the
//! TLS protocol.
//!
//! The main config and connection items are brought into the top level namespace
//! so that they can be accessed as `cohort::OpenSslConnection` or `cohort::S2NConnection`.
//! Modules are also public so that utility structs can be accessed, like
//! `cohort::s2n_tls::SessionTicketStorage`.

pub mod openssl;
pub mod rustls;
pub mod s2n_tls;

// NOTE: BoringSSL is disabled on macOS to avoid symbol collisions with
// OpenSSL; see https://github.com/aws/s2n-tls/pull/5659 for details.
#[cfg(not(target_os = "macos"))]
pub mod boringssl;

pub use openssl::{OpenSslConfig, OpenSslConnection};
pub use rustls::{RustlsConfig, RustlsConnection};
pub use s2n_tls::{S2NConfig, S2NConnection};

#[cfg(not(target_os = "macos"))]
pub use boringssl::{BoringSslConfig, BoringSslConnection};
