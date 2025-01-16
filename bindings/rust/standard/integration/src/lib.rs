// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(all(not(feature = "no-network-tests"), test))]
mod network;

#[cfg(test)]
mod tests {
    use s2n_tls::{
        security::Policy,
        testing::{self, TestPair},
    };

    /// This test provides a helpful debug message if the PQ feature is incorrectly
    /// configured.
    #[cfg(feature = "pq")]
    #[test]
    fn pq_sanity_check() -> Result<(), Box<dyn std::error::Error>> {
        let config = testing::build_config(&Policy::from_version("default_pq")?)?;
        let mut pair = TestPair::from_config(&config);
        pair.handshake()?;

        if pair.client.kem_group_name().is_none() {
            panic!(
                "PQ tests are enabled, but PQ functionality is unavailable. \
                Are you sure that the libcrypto supports PQ?"
            );
        }
        Ok(())
    }
}
