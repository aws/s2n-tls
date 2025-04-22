# JUnit Snapshot Testing Utility

A command-line tool for capturing, managing, and comparing JUnit XML test results.

## Features

- Capture snapshots of JUnit XML test results
- Compare new test results against baseline snapshots
- Track test status changes over time
- Detect new, missing, or changed tests
- Git integration for tracking commits and branches

## Installation

```bash
cargo install --path .
```

## Usage

### Initialize a snapshot directory

```bash
junit-snapshot init [DIR]
```

### Capture a snapshot from JUnit XML files

```bash
junit-snapshot capture [FILES...] [--name NAME] [--description DESC] [--dir DIR]
```

### List available snapshots

```bash
junit-snapshot list [--dir DIR]
```

### Show details of a specific snapshot

```bash
junit-snapshot show ID [--dir DIR]
```

### Compare a new JUnit file against a baseline snapshot

```bash
junit-snapshot compare FILE BASELINE_ID [--dir DIR] [--diff-only] [--fail-on-diff]
```

Options:
- `--diff-only`: Only show differences (hide matching tests)
- `--fail-on-diff`: Exit with non-zero status if differences are found

### Delete a snapshot

```bash
junit-snapshot delete ID [--dir DIR]
```

## Example Workflow

1. Initialize a snapshot directory:
   ```bash
   junit-snapshot init ./snapshots
   ```

2. Capture a baseline snapshot:
   ```bash
   junit-snapshot capture ./test-results.xml --name "baseline" --dir ./snapshots
   ```

3. Run tests again and compare with baseline:
   ```bash
   junit-snapshot compare ./new-test-results.xml SNAPSHOT_ID --dir ./snapshots
   ```

4. Use in CI to fail if tests change unexpectedly:
   ```bash
   junit-snapshot compare ./test-results.xml BASELINE_ID --fail-on-diff
   ```

## Development

### Running Tests

```bash
cargo test
```

### Building

```bash
cargo build --release
```
