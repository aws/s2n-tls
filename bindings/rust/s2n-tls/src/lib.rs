// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

#[macro_use]
pub mod error;

pub mod callbacks;
pub mod config;
pub mod connection;
pub mod enums;
pub mod init;
pub mod pool;
pub mod security;

pub use s2n_tls_sys as ffi;

#[cfg(any(feature = "testing", test))]
pub mod testing;
