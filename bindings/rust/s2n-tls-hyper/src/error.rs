// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};

/// Indicates which error occurred.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Indicates that the scheme in the URI provided to the `HttpsConnector` is invalid.
    InvalidScheme,
    /// Indicates that an error occurred in the underlying `HttpConnector`.
    HttpError(Box<dyn std::error::Error + Send + Sync>),
    /// Indicates that an error occurred in s2n-tls.
    TlsError(s2n_tls::error::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidScheme => write!(f, "The provided URI contains an invalid scheme."),
            Error::HttpError(err) => write!(f, "{}", err),
            Error::TlsError(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for Error {}
