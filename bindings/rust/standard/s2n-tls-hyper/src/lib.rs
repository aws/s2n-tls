// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![warn(missing_docs)]

//! This crate provides compatibility structs for the [hyper](https://hyper.rs/) HTTP library,
//! allowing s2n-tls to be used as the underlying TLS implementation to negotiate HTTPS with hyper
//! clients.
//!
//! `s2n-tls-hyper` provides an `HttpsConnector` struct which is compatible with the
//! `hyper_util::client::legacy::Client` builder, allowing hyper clients to be constructed with
//! configurable s2n-tls connections. The following example demonstrates how to construct a hyper
//! client with s2n-tls:
//!
//! ```
//! use std::str::FromStr;
//! use hyper_util::{
//!     client::legacy::Client,
//!     rt::TokioExecutor,
//! };
//! use s2n_tls_hyper::connector::HttpsConnector;
//! use s2n_tls::config::Config;
//! use bytes::Bytes;
//! use http_body_util::Empty;
//! use http::uri::Uri;
//!
//! // An `HttpsConnector` is built with an `s2n_tls::connection::Builder`, such as an
//! // `s2n_tls::config::Config`, which allows for the underlying TLS connection to be configured.
//! let config = Config::default();
//!
//! // The `HttpsConnector` wraps hyper's `HttpConnector`. `HttpsConnector::new()` will create
//! // a new `HttpConnector` to wrap.
//! let connector = HttpsConnector::new(Config::default());
//!
//! // The `HttpsConnector` can then be provided to the hyper Client builder, which can be used to
//! // send HTTP requests over HTTPS by specifying the HTTPS scheme in the URL.
//! let client: Client<_, Empty<Bytes>> =
//!     Client::builder(TokioExecutor::new()).build(connector);
//! ```

/// Provides the `HttpsConnector` struct.
pub mod connector;

/// Provides errors returned by s2n-tls-hyper.
pub mod error;

mod stream;
