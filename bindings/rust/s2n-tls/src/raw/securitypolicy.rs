// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
pub struct SecurityPolicy{
    pub version: &'static str,
}

pub const DEFAULT: SecurityPolicy = SecurityPolicy{version: "default"};
pub const DEFAULT_TLS13: SecurityPolicy = SecurityPolicy{version: "default_tls13"};

pub const ALLPOLICIES:[SecurityPolicy; 2] = [DEFAULT,DEFAULT_TLS13];
