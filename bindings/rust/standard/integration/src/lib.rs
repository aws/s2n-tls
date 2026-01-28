// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
/// the `pems` folder storing most of the s2n-tls unit test certs
const TEST_PEMS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../tests/pems/");

#[cfg(test)]
mod capability_check;
#[cfg(test)]
mod features;
#[cfg(test)]
mod handshake_failure_errors;
#[cfg(test)]
mod mtls;
#[cfg(all(not(feature = "no-sensitive-tests"), test))]
mod network;
#[cfg(test)]
mod signature_aware_selection;
