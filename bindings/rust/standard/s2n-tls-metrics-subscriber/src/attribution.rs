// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// Identifies the source of a metric record by service, resource, and component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Attribution {
    /// The service or application name (e.g. "my-tls-service")
    pub service: String,
    /// The resource producing metrics (e.g. an ARN or listener name)
    pub resource: String,
    /// Distinguishes telemetry from multiple components within the same
    /// application. For example, a load balancer application might want to
    /// record both "frontend" and "backend" telemetry. Leave empty to emit
    /// just "TlsTelemetry" without a component suffix.
    pub component: String,
}
