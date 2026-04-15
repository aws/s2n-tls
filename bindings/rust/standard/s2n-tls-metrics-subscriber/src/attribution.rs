// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Identifies the source of a metric record by service and resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Attribution {
    /// The service or application name (e.g. "my-tls-service")
    pub service: String,
    /// The resource producing metrics (e.g. an ARN or listener name)
    pub resource: String,
}
