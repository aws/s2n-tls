// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serialization schema types for s2n-tls metrics.
//!
//! This crate provides the wire-format types used to serialize and deserialize
//! TLS metric records. It has no stability guarantees and may change between
//! minor versions.

pub mod attribution;
pub mod bounded_set;
pub mod counter;
pub mod label;
pub mod record;
pub mod static_lists;
