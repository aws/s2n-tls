// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod utilities;
#[cfg(test)]
use utilities::capability_check;
#[cfg(test)]
mod handshake;
#[cfg(test)]
mod mtls;
#[cfg(all(not(feature = "no-sensitive-tests"), test))]
mod network;
#[cfg(test)]
mod record;
