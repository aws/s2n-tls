# Fuzz Tests

Requires nightly Rust and `cargo-fuzz`:

```sh
cargo install cargo-fuzz
```

## Run

```sh
# Run indefinitely (Ctrl+C to stop)
cargo +nightly fuzz run fuzz_cert_parse

# Run for a fixed duration
cargo +nightly fuzz run fuzz_cert_parse -- -max_total_time=60

# Run with multiple parallel jobs
cargo +nightly fuzz run fuzz_cert_parse --jobs 31
```

## List targets

```sh
cargo +nightly fuzz list
```

## Reproduce a crash

```sh
cargo +nightly fuzz run fuzz_cert_parse artifacts/fuzz_cert_parse/<crash_file>
```
