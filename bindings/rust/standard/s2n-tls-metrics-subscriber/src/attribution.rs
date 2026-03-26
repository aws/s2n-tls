// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Identifies the source of a metric record by service and resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribution {
    /// The service or application name (e.g. "my-tls-service")
    pub platform: Arc<str>,
    /// The individual resource or listener name (e.g. "api-gateway-listener")
    pub resource: Arc<str>,
}
