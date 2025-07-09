```shell
cargo +nightly fuzz run client_hello -- -max_total_time=30
cargo +nightly fuzz run psk_client_hello -- -max_total_time=30
```