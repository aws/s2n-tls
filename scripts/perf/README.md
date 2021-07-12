# Performance Runner

## Requirements

* Linux
* Cargo

## Generating a Flamegraph


```bash
./scripts/perf/run
```

## Overrides

By default the test will download 1GB worth of data from the server to client, with the `default`
security policy. This can be changed with the script arguments:

```bash
# <download bytes> <upload bytes> <security policy>
./scripts/perf/run 123 456 default_tls13
```

