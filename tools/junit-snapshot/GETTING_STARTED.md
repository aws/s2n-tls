# Getting Started with junit-snapshot

This guide will help you get started with the junit-snapshot tool, which allows you to create and manage snapshots of JUnit XML test results for comparison and regression testing.

## Prerequisites

- Rust and Cargo installed on your system
- Access to JUnit XML test result files (typically generated from test runs)

## Building the Tool

Install the junit-snapshot tool using Cargo:

```bash
cd tools/junit-snapshot
cargo install --path .
```

This will compile the tool and install it to your Cargo binary directory (typically `~/.cargo/bin/`), which should already be in your PATH. You can now run `junit-snapshot` from anywhere on your system.

If you prefer to build without installing:

```bash
cd tools/junit-snapshot
cargo build
```

Then run it directly with:

```bash
./target/debug/junit-snapshot
```

## Basic Workflow

The typical workflow for using junit-snapshot involves:

1. Initialize a snapshot directory
2. Capture initial snapshots from test results
3. Run tests and compare new results against snapshots
4. Update snapshots when expected changes occur

## Step 1: Initialize a Snapshot Directory

Before capturing snapshots, you need to initialize a snapshot directory:

```bash
# Initialize in the current directory
junit-snapshot init

# Or specify a different directory
junit-snapshot init /path/to/snapshots
```

This creates the necessary structure to store and manage snapshots.

## Step 2: Capture Initial Snapshots

After running your tests and generating JUnit XML files, capture snapshots:

```bash
# Capture a snapshot from a single file
junit-snapshot capture path/to/junit-results.xml --name "baseline" --description "Initial baseline snapshot"

# Capture snapshots from multiple files
junit-snapshot capture path/to/results1.xml path/to/results2.xml --name "multi-baseline"

# Specify a different snapshot directory
junit-snapshot capture path/to/results.xml --dir /path/to/snapshots
```

## Step 3: List Available Snapshots

To see what snapshots are available:

```bash
# List snapshots in the current directory
junit-snapshot list

# List snapshots in a specific directory
junit-snapshot list --dir /path/to/snapshots
```

## Step 4: Compare Test Results Against Snapshots

After making changes to your code, run your tests again and compare the new results against the existing snapshots:

```bash
# Compare a new test result against the latest snapshot
junit-snapshot compare path/to/new-results.xml

# Compare against a specific snapshot by ID
junit-snapshot compare path/to/new-results.xml --id 20250422_123456

# Compare and generate a detailed report
junit-snapshot compare path/to/new-results.xml --report report.html
```

## Step 5: Update Snapshots

When you've made intentional changes that affect test results, update your snapshots:

```bash
# Update the latest snapshot with new results
junit-snapshot update path/to/new-results.xml

# Update a specific snapshot by ID
junit-snapshot update path/to/new-results.xml --id 20250422_123456

# Create a new snapshot instead of updating
junit-snapshot capture path/to/new-results.xml --name "updated-baseline"
```

## Working with Integration Tests

For s2n-tls integration tests, you'll typically work with the XML files in the `tests/integrationv2/` directory:

```bash
# Initialize a snapshot directory for integration tests
mkdir -p tests/integrationv2/.snapshots
junit-snapshot init tests/integrationv2/.snapshots

# After running integration tests, capture the results
junit-snapshot capture report_integ-integrationv2_*.xml --dir tests/integrationv2/.snapshots

# Compare new test results after code changes
junit-snapshot compare report_integ-integrationv2_*.xml --dir tests/integrationv2/.snapshots
```

## Best Practices

1. **Version Control**: Commit your snapshots to version control to track changes over time.

2. **Meaningful Names**: Use descriptive names and descriptions for your snapshots to make them easier to identify.

3. **Regular Updates**: Update snapshots when you make intentional changes that affect test behavior.

4. **Review Changes**: Always review the differences between snapshots before updating to ensure changes are expected.

5. **CI Integration**: Integrate snapshot testing into your CI pipeline to catch regressions automatically.

## Example Workflow

Here's a complete example workflow:

```bash
# Initialize snapshot directory
junit-snapshot init tests/.snapshots

# Run tests and generate JUnit XML
make run-tests

# Capture initial snapshot
junit-snapshot capture tests/results.xml --name "baseline" --dir tests/.snapshots

# Make code changes...

# Run tests again
make run-tests

# Compare new results against snapshot
junit-snapshot compare tests/results.xml --dir tests/.snapshots

# If changes are expected, update the snapshot
junit-snapshot update tests/results.xml --dir tests/.snapshots
```

## Troubleshooting

- **XML Parsing Errors**: Ensure your JUnit XML files are well-formed and valid.
- **Missing Snapshots**: Check that you're using the correct snapshot directory with `--dir`.
- **Permission Issues**: Verify you have write permissions to the snapshot directory.

## Advanced Usage

For more advanced usage and options, run:

```bash
junit-snapshot --help
```

Or for help with a specific command:

```bash
junit-snapshot <command> --help
```

## Contributing

If you encounter issues or have suggestions for improving the junit-snapshot tool, please open an issue or submit a pull request to the s2n-tls repository.
