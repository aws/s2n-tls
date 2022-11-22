// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Application specific error codes.
#[non_exhaustive]
#[derive(Clone, PartialEq)]
pub enum ApplicationError {
    #[non_exhaustive]
    /// An error occurred while running custom callback code.
    ///
    /// Use [`ApplicationError::callback_execution()`] to construct an instance.
    /// Can be emitted from [`callbacks::AsyncClientHelloFuture::poll_client_hello()`]
    /// to indicate a failure from the async task.
    CallbackExection {},
}

impl ApplicationError {
    pub fn callback_execution() -> Self {
        Self::CallbackExection {}
    }
}

impl From<ApplicationError> for super::Error {
    fn from(err: ApplicationError) -> Self {
        match err {
            ApplicationError::CallbackExection {} => super::Error::CALLBACK_EXECUTION,
        }
    }
}
