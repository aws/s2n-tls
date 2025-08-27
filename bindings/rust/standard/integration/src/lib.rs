// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod capability_check;
#[cfg(test)]
mod features;
#[cfg(all(not(feature = "no-network-tests"), test))]
mod network;
