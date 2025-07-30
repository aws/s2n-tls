# Goal

Propose a TLS auth solution that scales better for large fleets by caching the ciphertext datakey in S3.

# Why

The `PskProvider` in `aws-kms-tls-auth` generates a unique datakey per host, which results in n^2 calls to bootstrap a fully connected mesh of clients and servers. This may be prohibitively expensive for large fleets, especially in "restart" scenarios.

# How

Clients will perform a simple version of leader election. The leader client (`PskProvider`) is responsible for generating a datakey ciphertext and caching it in S3. Other clients will use this cached ciphertext instead of generating their own. Because the fleet will only be using one ciphertext, there will be `O(n)` calls to KMS. Specifically, there will be `n` decrypt calls - one for each client and server, as well as one `generate_data_key` call for the elected client.

## Design

> [!NOTE]  
> Describing algorithms in words is tricky. I'd start with the text for an overall understanding, and then read through the "Pseudocode" section in the appendix for a more exact specification.

### Leader Election

Time is divided into epochs, which refers to the number of rotation periods since the unix epoch. For a 24 hour rotation period this will be the number of days since the unix epoch.

When a client starts up, it generates a random number between `0` and `ROTATION_PERIOD_NANOSECONDS` as its `ID`. E.g. for a 24 hour rotation period this would be a number between `0` and `86400000000`.

On startup a client will check S3 for the key of the current epoch, which is stored at `ciphertext_{epoch_number}.key`. 
- if no key exists, then it immediately attempts to elect itself leader, generating a ciphertext and uploading it to S3.
- if a key exists but the leader's ID was greater than it's own, it attempts to elect itself for the next epoch.
- if a key exists and the leader's ID was less than or equal to it's own, then the client decrypts the ciphertext and uses it as the PSK.

When a client is the leader, It will take the following action: 
- When `ID` seconds have elapsed in the current epoch `n`, generate a new key for epoch `n + 1` and store it in S3.

All clients (including the leader) take the following actions
- When `ID` seconds have elapsed in the current epoch `n`, retrieve the `n` ciphertext from S3, decrypt it, and use it as the PSK.

In this system, the number of calls to KMS is `O(n)`. Client `decrypt` calls will happen uniformly throughout the rotation period. Server `decrypt` calls will happen as the clients pickup up the new ciphertext. The maximum traffic spike to KMS would be `O(n)`, and would happen if a the first client to use a new ciphertext immediately connected to all servers after it switched to the new ciphertext.

### Object Structure
The object name is `ciphertext_{epoch_number}.json`.

The object contains the following fields
- `datakey_ciphertext`: The base64-encoded KMS datakey ciphertext.
- `leader_id`: The ID of the leader which generated the key.

### Cache
We use S3. DynamoDB doesn't work well when all of the traffic is concentrated against a single key.

> You should design your application for uniform activity across all partition keys in the table and its secondary indexes. You can determine the access patterns that your application requires, and read and write units that each table and secondary index requires.
> https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-partition-key-design.html

We will use conditional writes to ensure that the distributed fleet has a consistent view of the state of the leader system

> The If-None-Match header prevents overwrites of existing data by validating that there's not an object with the same key name already in your bucket.
> Alternatively, you can add the If-Match header to check an object's entity tag (ETag) before writing an object. With this header, Amazon S3 compares the provided ETag value with the ETag value of the object in S3. If the ETag values don't match, the operation fails.
> https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html

Correspondingly, the S3 bucket must have versioning enabled.

# Scenario Appendix

### System Startup 👶
In a system cold start, all clients would attempt to elect themselves because there would be no keys. This would result in an `O(n)` spike of generate data key calls to KMS.

In this case, all of the attempts to write to S3 would be conditional using `If-None-Match`.
> Conditional writes can ensure there is no existing object with the same key name in your bucket during PUT operations. This prevents overwriting of existing objects with identical key names.
> https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-requests.html
> https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html

So clients would race each other to write to S3. One client will win the race, but that client might not actually be the lowest ID.

Consider a system startup where clients have the following IDs `1, 2, 3, 4`. 

By random chance, `3` might be the first to write to S3. The other conditional writes would fail. Because `3` is now the leader it would also generate the ciphertext for epoch `n + 1`.

At this point `1`, `2`, and `4` will read the ciphertext from S3. 

- `4` will read the ciphertext, see that `3 < 4`, and then decrypt the ciphertext and start using it as it's PSK
- `2` will read the ciphertext, see that `3 > 2`, and attempt self-election. This means that it will generate a data-key, and then attempt to overwrite the key for epoch `n + 1` using a `If-Match` write condition for the observed object version.
- `1` will read the ciphertext, see that `3 > 1`, and attempt self-election through the same process as `2`.

Because `1` and `2` are both using `If-Match` conditions, only one of the writes will succeed. The client that fails will then re-read the ciphertext from S3, checking the new leader id.

If `2` was the client whose first write succeeded, then `1` would attempt to overwrite using `If-Match` against the latest version, which would succeed.
If `1` was the client whose first write succeeded, then `2` would read the new key and give up on coronation, because `1 < 2`.

In summary, a random client will be elected leader for the current system epoch `n`. All clients will use that key for epoch `n`. The "correct" leader will be established by epoch `n + 1`.

### Leader Deposed 🔫

Leaders may die. 

This could happen if a host crashes, is taken out of service, etc. 

If a leader dies during epoch `n`, the system is stable for epoch `n` and `n + 1` because the keys were already generated. During epoch `n + 2`, the client with the lowest ID will be the first to check for the `n + 2` key. Once it sees that there is no key, it will self-elect and store a new ciphertext in S3.

However, there is expected to be much less contention, because clients will not all be checking for key `n + 2` at the same time, because they only check `ID` seconds into the new epoch.

### Leader Uprising 👑

A new, more powerful leader may be born. 

If a new, superior client is born in epoch `n` it will retrieve the key for epoch `n` and noticed that it should be the new leader. It will then retrieve the key for epoch `n + 1`, checking the leader ID. If it's ID is lower, then it will attempt overwrite the key for `n + 1` using an `If-Match` PutObject condition. 

### Leader Collision 👸⚔️👸

Clients are not guaranteed to have unique IDs. This is fine.

A client will only start the leader coronation process if it's ID is strictly less than the existing leader. 


### Pseudocode

```rust
struct Key {
    // the ciphertext datakey which can be decrypted with KMS
    ciphertext: Vec<u8>,
    // the ID of the leader who generated this key
    leader_id: u64
}

const ROTATION_PERIOD_NS: u64 = 86400000000;
fn client_lifecycle() {
    let mut leader: bool = false;
    // startup
    let id: u64 = random_between(0, ROTATION_PERIOD_NS);

    // the first iteration of the loop runs immediately on startup
    loop {
        let current_epoch: u64 = current_epoch(SystemTime::now(), ROTATION_PERIOD_NS);

        let current_key: Key = match s3.get_object("ciphertext_{current_epoch}.json") {
            Some(key) => {
                if key.leader_id > id {
                    // the existing leader is worse than we are, depose them
                    leader = true;
                }
                key
            },
            None => {
                // there is no key so we should generate one
                let new_key = generate_key();
                let result = s3.put_object("ciphertext_{current_epoch}.json", Precondition.IfNoneMatch);
                match result {
                    Ok(key) => {
                        // we won the race to put in the key
                        leader = true;
                        key
                    }
                    Err(_) => {
                        // someone else won the race to put in the key
                        // return the key that they stored
                        s3.get_object(current_epoch).unwrap();
                    }
                }
            }
        }

        // at this point `current_key` is the key that will be used for the remainder
        // of the epoch

        // try nomination
        if leader {
            let next_epoch: u64 = current_epoch + 1;
            loop {
                match s3.get_object("ciphertext_{next_epoch}.json") {
                    None => {
                        // no one else has tried to nominate themselves as the next leader
                        let new_key = generate_key();
                        let result = s3.put_object("ciphertext_{next_epoch}.json", Precondition.IfNoneMatch);
                        if result.is_ok() {
                            // we won the race and are the leader, no further action.
                            break; 
                        }
                        // otherwise we'll need to check the new key
                    }
                    Some(proposed_key) => {
                        if proposed_key.leader_id < id {
                            // someone else elected themselves leader, and they 
                            // are superior to us
                            leader = false;
                            break;
                        } else {
                            // they are inferior to us. We deserve the crown!
                            let new_key = generate_key();
                            let result = s3.put_object("ciphertext_{next_epoch}.json", Precondition.IfMatch(proposed_key.version));
                            if result.is_ok() {
                                // we overwrote the inferior key, no further action
                                break; 
                            }
                            // someone else overwrote the key first, check the new key
                        }
                    }
                }
            }
        }

        let next_epoch = get_epoch_start(current_epoch + 1)
        let next_key_check = next_epoch + Duration::from_ns(id);
        std::thread::sleep_until(next_key_check).await;
    }
}
```