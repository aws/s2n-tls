// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[non_exhaustive]
pub enum ApplicationError {
    #[non_exhaustive]
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
