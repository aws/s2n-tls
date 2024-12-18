use async_pkey_offload::{DEMO_REGION, KEY_DESCRIPTION};
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

    // list all KMS keys
    let key_list = client.list_keys().send().await?;
    if key_list.truncated {
        // assumption: key list should be small enough to not require pagination
        return Err("key list should not be truncated".into());
    }

    let keys = match key_list.keys {
        Some(keys) => keys,
        // no keys to delete, can immediately return
        None => return Ok(()),
    };

    for k in keys {
        let describe_output = client
            .describe_key()
            .key_id(k.key_id().unwrap())
            .send()
            .await?;

        let metadata = match describe_output.key_metadata {
            Some(metadata) => metadata,
            None => continue,
        };

        // this key is already scheduled for deletion
        if metadata.deletion_date.is_some() {
            continue;
        }

        if metadata.description() == Some(KEY_DESCRIPTION) {
            println!("scheduling {:?} for deletion", k.key_id().unwrap());
            client
                .schedule_key_deletion()
                .key_id(k.key_id().unwrap())
                .send()
                .await?;
        }
    }

    Ok(())
}
