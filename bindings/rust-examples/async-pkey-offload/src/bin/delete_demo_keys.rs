// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use async_pkey_offload::{get_demo_keys, DEMO_REGION};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::Client;

/// This is a small helper script used to delete any keys that might have been
/// created by the demo.
///
/// It will iterate over all the KMS keys and schedule the deletion of any keys
/// where the key description is [crate::KEY_DESCRIPTION]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let shared_config = aws_config::defaults(BehaviorVersion::v2024_03_28())
        .region(Region::from_static(DEMO_REGION))
        .load()
        .await;

    let client = Client::new(&shared_config);

    let demo_key_ids = get_demo_keys(&client).await?;

    if demo_key_ids.is_empty() {
        // no keys to delete, can immediately return
        return Ok(());
    }

    for k in demo_key_ids {
        println!("scheduling {:?} for deletion", k);
        client.schedule_key_deletion().key_id(k).send().await?;
    }

    Ok(())
}
